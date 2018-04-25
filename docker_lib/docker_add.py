#!coding=utf-8
# 接受指令，开启一个docker容器，并返回一个容器id。
# 接受指令，新建一个docker镜像，并返回一个镜像id。

from docker import errors as docker_errors
from . import logger


class Dokcers_Add():

    def __init__(self, client):
        super(Dokcers_Add, self).__init__()
        self.client = client

    # 使用docker pull获取一个docekr镜像
    def Add_Images(self, Images_Name, Images_Tag = 'latest'):
        '''
        :param Images_Name: pull的镜像名字
        :param Images_Tag: 镜像的标签，默认是latest
        :return: docker镜像对象。
        '''

        try:
            Images = self.client.images.pull(Images_Name, Images_Tag)
            logger.info('创建一个镜像，镜像ID为：%s' % Images.id)
        except docker_errors.APIError as e:
            logger.warning('Pull一个容器失败，因为Docker服务出错！')
            return False
        return Images



    # 开启一个容器
    def Start_Containers(self, Images_Id, Ports, Mem_Limit = '', Command = '', Volumes_Path = {}):
        '''

        :param Images_Id: 使用的镜像ID
        :param Mem_Limit: 设置分配的内存大小，默认为30M。
        :param Ports: 开启容器转发的端口，是一个字典类型的参数，容器端口对应主机端口，eg：{'2222/tcp': 3333,'1111/tcp': ('127.0.0.1', 1111)}，{'1111/tcp': [1234, 4567]}
        :param Command: 启动容器时运行的命令，默认为空，一般我们不需要修改这个参数。
        :param Volumes_Path: 启动容器时挂载的目录，默认为空。类型是一个字典。eg：{'/home/user1/': {'bind': '/mnt/vol2', 'mode': 'rw'},
 '/var/www': {'bind': '/mnt/vol1', 'mode': 'ro'}} ，bind The path to mount the volume inside the container
mode Either rw to mount the volume read/write, or ro to mount it read-only.
        :return: 返回一个容器ID
        '''

        try:
            Containers = self.client.containers.run(Images_Id, \
                                                       detach = True, \
                                                       mem_swappiness = 0, \
                                                       auto_remove = True, \
                                                       ports = Ports, \
                                                       command = Command, \
                                                       volumes = Volumes_Path
                                                    )
            logger.info('创建一个容器，容器ID为：%s' % Containers.id)

        except docker_errors.ContainerError as e:
            logger.warning('创建一个容器失败，因为容器以非零退出代码退出并且分离！')
            return False
        except docker_errors.ImageNotFound as e:
            logger.warning('创建一个容器失败，因为指定的容器不存在！')
            return False
        except docker_errors.APIError as e:
            logger.warning('创建一个容器失败，因为Docker服务出错！')
            return False

        return Containers.id






