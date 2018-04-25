#!coding=utf-8
# 接受指令，删除一个docker容器，并返回true或false。
# 接受指令，删除一个docker镜像，并返回true或false。

from docker import errors as docker_errors
from . import logger

class Dokcers_Del():

    def __init__(self, client):
        super(Dokcers_Del, self).__init__()
        self.client = client

    # 删除一个镜像
    def Remove_Images(self, Images_Id):
        '''

        :param Images_Id:  一个镜像的ID
        :return: true或者false
        '''

        try:
            self.client.images.remove(image = Images_Id)
            logger.info('删除了一个镜像，镜像ID是：%s' % Images_Id)

        except docker_errors.APIError as e:
            logger.warning('删除镜像失败，因为Docker服务出错！')
            return False

        return True


    # 停止一个容器
    def Stop_Containers(self, Con):
        '''

        :param Con: 一个docker容器的对象，需要先使用docker_get.Get_Images_Message()获取一个容器对象。
        :return: true或false
        '''
        try:
            Con.remove(v = True, force = True)
            logger.info('停止了一个容器，容器ID是：%s' % Con.id)
        except docker_errors.APIError as e:
            logger.warning('停止容器失败，因为Docker服务出错！')
            return False

        return True
