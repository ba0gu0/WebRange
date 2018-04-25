#! coding=utf-8
# 初始化docker模块，直接提供三个控制借口，可以直接操作docker镜像和容器。
import docker

from log.logger import logger
from docker_lib.docker_add import Dokcers_Add
from docker_lib.docker_del import Dokcers_Del
from docker_lib.docker_get import Dokcers_Get

try:
    client = docker.from_env()
    client.images.list()
    logger.info('连接到Docker进程。')
except Exception as e :
    logger.warning('连接本地Docker进程失败，可能是Docker进程未开启！')
    exit()

Dockers_Start = Dokcers_Add(client)
Dockers_Stop = Dokcers_Del(client)
Dockers_Info = Dokcers_Get(client)

