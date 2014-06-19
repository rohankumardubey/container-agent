#!/usr/bin/python

# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Launch containers specified by a Google container manifest.

This program interprets a blob of JSON or YAML as a container manifest and
launches those containers.  This assumes that the system's docker daemon runs
with the -r=false flag, otherwise the docker daemon itself will try to do
restarts whenever it gets a signal itself.

This will read one file, specified on the commandline, or stdin if no file is
provided.

This will log to syslog's LOCAL3 facility.

Environmental requirements:
  - Docker 0.11 or higher
  - Docker daemon runs with -r=false (for safer restart behavior)

"""

import logging
import os
import re
import sys
import time
import yaml

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from logging import WARNING, DEBUG
from logging.handlers import SysLogHandler
from hashlib import sha1

from docker_client import CliDockerClient

log = logging.getLogger(__name__)


SUPPORTED_CONFIG_VERSIONS = ['v1beta1']

PROTOCOL_TCP = 'TCP'
PROTOCOL_UDP = 'UDP'
VALID_PROTOCOLS = [PROTOCOL_TCP, PROTOCOL_UDP]

RE_RFC1035_NAME = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])*$")
RE_C_TOKEN = re.compile(r"[A-Za-z_]\w*$")
MAX_PATH_LEN = 512

DOCKER_CMD = 'docker'
VOLUMES_ROOT_DIR = '/export'


def IsValidProtocol(proto):
    return proto in VALID_PROTOCOLS


def ProtocolString(proto):
    if proto == PROTOCOL_UDP:
        return '/udp'
    return ''


def IsValidPort(port):
    return 0 < port <= 65535


def IsRfc1035Name(name):
    return RE_RFC1035_NAME.match(name)


def IsCToken(name):
    return RE_C_TOKEN.match(name)


def IsValidPath(path):
    return path[0] == '/' and len(path) <= MAX_PATH_LEN


def LoadVolumes(volumes):
    """Process a "volumes" block of config and return a list of volumes."""

    # TODO(thockin): could be a map of name -> Volume
    all_vol_names = []
    for vol_index, vol in enumerate(volumes):
        # Get the container name.
        if 'name' not in vol:
            raise Exception('volumes[%d] has no name' % (vol_index))
        vol_name = vol['name']
        if not IsRfc1035Name(vol_name):
            raise Exception('volumes[%d].name is invalid: %s' % (vol_index, vol_name))
        if vol_name in all_vol_names:
            raise Exception('volumes[%d].name is not unique: %s' % (vol_index, vol_name))
        all_vol_names.append(vol_name)

    return all_vol_names


# TODO(thockin): We should probably fail on unknown fields in JSON objects.
class Container(object):

    """The accumulated parameters to start a Docker container."""

    # Only allow the supported params.
    __slots__ = ('name', 'image', 'command', 'hostname', 'working_dir',
                 'ports', 'mounts', 'env_vars')

    def __init__(self, name, image):
        self.name = name          # required str
        self.image = image        # required str
        self.command = []         # list[str]
        self.hostname = None      # str
        self.working_dir = None   # str
        self.ports = []           # [(int, int, str)]
        self.mounts = []          # [str]
        self.env_vars = []        # [str]


def LoadUserContainers(containers, all_volumes):
    """Process a "containers" block of config and return a list of
    containers."""

    # TODO(thockin): could be a dict of name -> Container
    all_ctrs = []
    all_ctr_names = []
    for ctr_index, ctr_spec in enumerate(containers):
        # Verify the container name.
        if 'name' not in ctr_spec:
            raise Exception('containers[%d] has no name' % (ctr_index))
        if not IsRfc1035Name(ctr_spec['name']):
            raise Exception('containers[%d].name is invalid: %s'
                            % (ctr_index, ctr_spec['name']))
        if ctr_spec['name'] in all_ctr_names:
            raise Exception('containers[%d].name is not unique: %s'
                            % (ctr_index, ctr_spec['name']))
        all_ctr_names.append(ctr_spec['name'])

        # Verify the container image.
        if 'image' not in ctr_spec:
            raise Exception('containers[%s] has no image' % (ctr_spec['name']))

        # The current accumulation of parameters.
        current_ctr = Container(ctr_spec['name'], ctr_spec['image'])

        # Always set the hostname for user containers.
        current_ctr.hostname = current_ctr.name

        # Get the commandline.
        current_ctr.command = ctr_spec.get('command', [])

        # Get the initial working directory.
        current_ctr.working_dir = ctr_spec.get('workingDir', None)
        if current_ctr.working_dir is not None:
            if not IsValidPath(current_ctr.working_dir):
                raise Exception('containers[%s].workingDir is invalid: %s'
                                % (current_ctr.name, current_ctr.working_dir))

        # Get the list of port mappings.
        current_ctr.ports = LoadPorts(
            ctr_spec.get('ports', []), current_ctr.name)

        # Get the list of volumes to mount.
        current_ctr.mounts = LoadVolumeMounts(
            ctr_spec.get('volumeMounts', []), all_volumes, current_ctr.name)

        # Get the list of environment variables.
        current_ctr.env_vars = LoadEnvVars(
            ctr_spec.get('env', []), current_ctr.name)

        all_ctrs.append(current_ctr)

    return all_ctrs


def LoadPorts(ports_spec, ctr_name):
    """Process a "ports" block of config and return a list of ports."""

    # TODO(thockin): could be a dict of name -> Port
    all_ports = []
    all_port_names = []
    all_host_port_nums = []

    for port_index, port_spec in enumerate(ports_spec):
        if 'name' in port_spec:
            port_name = port_spec['name']
            if not IsRfc1035Name(port_name):
                raise Exception('containers[%s].ports[%d].name is invalid: %s'
                                % (ctr_name, port_index, port_name))
            if port_name in all_port_names:
                raise Exception('containers[%s].ports[%d].name is not unique: %s'
                                % (ctr_name, port_index, port_name))
            all_port_names.append(port_name)
        else:
            port_name = str(port_index)

        if 'containerPort' not in port_spec:
            raise Exception('containers[%s].ports[%s] has no containerPort'
                            % (ctr_name, port_name))
        ctr_port = port_spec['containerPort']
        if not IsValidPort(ctr_port):
            raise Exception('containers[%s].ports[%s].containerPort is invalid: %d'
                            % (ctr_name, port_name, ctr_port))

        host_port = port_spec.get('hostPort', ctr_port)
        if not IsValidPort(host_port):
            raise Exception('containers[%s].ports[%s].hostPort is invalid: %d'
                            % (ctr_name, port_name, host_port))
        if host_port in all_host_port_nums:
            raise Exception('containers[%s].ports[%s].hostPort is not unique: %d'
                            % (ctr_name, port_name, host_port))
        all_host_port_nums.append(host_port)

        proto = port_spec.get('protocol', 'TCP')
        if not IsValidProtocol(proto):
            raise Exception('containers[%s].ports[%s].protocol is invalid: %s'
                            % (ctr_name, port_name, proto))

        all_ports.append((host_port, ctr_port, ProtocolString(proto)))

    return all_ports


def LoadVolumeMounts(mounts_spec, all_volumes, ctr_name):
    """Process a "volumeMounts" block of config and return a list of mounts."""

    # TODO(thockin): Could be a dict of name -> Mount
    all_mounts = []
    for vol_index, vol_spec in enumerate(mounts_spec):
        if 'name' not in vol_spec:
            raise Exception('containers[%s].volumeMounts[%d] has no name'
                            % (ctr_name, vol_index))
        vol_name = vol_spec['name']
        if not IsRfc1035Name(vol_name):
            raise Exception('containers[%s].volumeMounts[%d].name'
                            'is invalid: %s'
                            % (ctr_name, vol_index, vol_name))
        if vol_name not in all_volumes:
            raise Exception('containers[%s].volumeMounts[%d].name'
                            'is not a known volume: %s'
                            % (ctr_name, vol_index, vol_name))

        if 'path' not in vol_spec:
            raise Exception('containers[%s].volumeMounts[%s] has no path'
                            % (ctr_name, vol_name))
        vol_path = vol_spec['path']
        if not IsValidPath(vol_path):
            raise Exception('containers[%s].volumeMounts[%s].path is invalid: %s'
                            % (ctr_name, vol_name, vol_path))

        read_mode = 'ro' if vol_spec.get('readOnly', False) else 'rw'

        all_mounts.append(
            '%s/%s:%s:%s' % (VOLUMES_ROOT_DIR, vol_name, vol_path, read_mode))

    return all_mounts


def LoadEnvVars(env_spec, ctr_name):
    """Process an "env" block of config and return a list of env vars."""

    # TODO(thockin): could be a dict of key -> value
    all_env_vars = []
    for env_index, env_spec in enumerate(env_spec):
        if 'key' not in env_spec:
            raise Exception('containers[%s].env[%d] has no key' % (ctr_name, env_index))
        env_key = env_spec['key']
        if not IsCToken(env_key):
            raise Exception('containers[%s].env[%d].key is invalid: %s'
                            % (ctr_name, env_index, env_key))

        if 'value' not in env_spec:
            raise Exception('containers[%s].env[%s] has no value' % (ctr_name, env_key))
        env_val = env_spec['value']

        all_env_vars.append('%s=%s' % (env_key, env_val))

    return all_env_vars


def CheckGroupWideConflicts(containers):
    # TODO(thockin): we could put other uniqueness checks (e.g. name) here.
    # Make sure not two containers have conflicting host or container ports.
    host_ports = set()
    for ctr in containers:
        for port in ctr.ports:
            h = '%s%s' % (port[0], port[2])
            if h in host_ports:
                raise Exception('host port %s is not unique group-wide' % (h))
            host_ports.add(h)


def FlagList(values, flag):
    """Turns a list of values into a list of flags.

    This takes a list of strings, and produces a new list with an extra string
    ('flag') between each value.

    Args:
      values: a list of strings
      flag: a string

    Returns:
      the expanded list of strings

    Example:
      FlagList(["a", "b", "c"], "-x") => ["-x", "a", "-x", "b", "-x", "c"]

    """

    result = []
    for v in values:
        result.extend([flag, v])
    return result


def FlagOrNothing(value, flag):
    """Turns a value into a flag list iff value is not None."""
    if value is not None:
        return [flag, value]
    return []


def StartContainer(docker, name, ctr):
    log.info("starting new container '%s'", ctr.name)
    docker.run(image=ctr.image,
               ports=ctr.ports,
               volumes=ctr.mounts,
               env=ctr.env_vars,
               command=ctr.command,
               name=name)


def RunContainer(docker, name, ctr):
    infos = docker.inspect_container(name)
    info = infos and infos[0]
    if info:
        running = info['State']['Running']
        if not running:
            exit_code = info['State']['ExitCode']
            log.info("restarting exited container '%s' (%d)", name, exit_code)
            docker.destroy(name)
            StartContainer(docker, name, ctr)
    else:
        StartContainer(docker, name, ctr)


def ContainerHash(ctr):
    m = sha1()
    m.update(yaml.dump(ctr))
    return m.hexdigest()[:8]


def RunContainers(containers, namespace):
    docker = CliDockerClient()
    prefix = '%s-' % (namespace, )
    named = dict(('%s%s-%s' % (prefix, ctr.name, ContainerHash(ctr)), ctr) for ctr in containers)

    # First reap containers that might collide with the desired state
    running = [name for name in docker.list_containers(prefix) if name.startswith(prefix)]
    for name in running:
        log.debug('in %s namespace: %s', namespace, name)
        if name not in named:
            log.info('reaping unwanted container: %s', name)
            docker.kill(name)

    # Implement desired state
    for name, ctr in named.iteritems():
        RunContainer(docker, name, ctr)


def CheckVersion(config):
    if 'version' not in config:
        raise Exception('config has no version field')
    if config['version'] not in SUPPORTED_CONFIG_VERSIONS:
        raise Exception("config version '%s' is not supported" % config['version'])


def RunContainersFromConfigFile(config_file, reload_interval, namespace):
    while True:
        try:
            log.debug('loading config file: %s', config_file)
            with open(config_file) as f:
                config = yaml.load(f)
            CheckVersion(config)
            all_volumes = LoadVolumes(config.get('volumes', []))
            user_containers = LoadUserContainers(config.get('containers', []),
                                                 all_volumes)
            CheckGroupWideConflicts(user_containers)
            RunContainers(user_containers, namespace)
        except Exception, e:
            log.error(e)
        finally:
            log.debug('sleeping %d seconds', reload_interval)
            time.sleep(float(reload_interval))


def main():
    parser = ArgumentParser(description='container-agent', formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--syslog', help='log to syslog', action='store_true')
    parser.add_argument('-v', '--verbosity', action='count', default=0)
    parser.add_argument('--namespace', default='container-agent')
    parser.add_argument('-r', '--reload', default=5, help='file reload interval')
    parser.add_argument('containers', metavar='containers.yaml')
    args = parser.parse_args()

    if args.syslog:
        facility = SysLogHandler.LOG_LOCAL0
        if sys.platform.startswith('darwin') and os.path.exists('/var/run/syslog'):
            handler = SysLogHandler('/var/run/syslog', facility)
        elif sys.platform.startswith('sunos'):
            handler = SysLogHandler(('127.0.0.1', logging.handlers.SYSLOG_UDP_PORT), facility)
        else:
            handler = SysLogHandler('/dev/log', facility)
        log.addHandler(handler)

    logging.basicConfig(format='%(asctime)s %(levelname)-7s %(filename)s:%(lineno)d %(message)s',
                        level=max(DEBUG, WARNING - args.verbosity * 10))

    format = "%(asctime)s.%(msecs)03d [%(process)d]: %(message)s"
    logging.basicConfig(level=logging.DEBUG, format=format,
                        datefmt='%Y-%m-%d %H:%M:%S')

    RunContainersFromConfigFile(args.containers, args.reload, args.namespace)

if __name__ == '__main__':
    main()
