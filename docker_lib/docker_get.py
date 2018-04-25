#!coding=utf-8
# 接受指令，获取一个docker容器信息，并返回。
# 接受指令，获取一个docker镜像信息，并返回。

from docker import errors as docker_errors
from . import logger


class Dokcers_Get():

    def __init__(self, client):
        super(Dokcers_Get, self).__init__()
        self.client = client

    # 获取所有的镜像信息
    def Get_All_Images_Message(self):
        '''

        :return: 获取所有主机中的docker镜像，返回一个镜像的对象组成的列表。
        '''

        try:
            Images_List = self.client.images.list()
            logger.info('获取到所有的镜像信息。')

        except docker_errors.APIError as e:
            logger.warning('获取镜像信息失败，因为Docker服务出错！')
            return False
        return Images_List

    # 获取一个镜像的信息
    def Get_Images_Message(self, Images_Name):
        '''

        :param Images_Name: 一个doker镜像名字
        :return: 获取到的docker镜像对象。
        '''
        try:
            Images = self.client.images.get(Images_Name)
            logger.info('获取到一个镜像信息，镜像ID是：%s' % Images.id)
        except docker_errors.ImageNotFound as e:
            logger.warning('获取镜像信息失败，因为不能够找到这个镜像！')
            return False
        except docker_errors.APIError as e:
            logger.warning('获取镜像信息失败，因为Docker服务出错！')
            return False
        return Images



    # 获取一个容器的信息
    def Get_Containers_Message(self, Containers_Id):
        '''

        :param Containers_Id: docker容器的ID
        :return: 一个docker容器的对象。
        '''

        try:
            Con = self.client.containers.get(Containers_Id)
            logger.info('获取到一个容器对象。')
        except docker_errors.NotFound as e:
            logger.warning('获取容器对象失败，因为不能够找到这个容器！')
            return False
        except docker_errors.APIError as e:
            logger.warning('获取容器对象失败，因为Docker服务出错！')
            return False
        return Con


    # 获取所有的容器信息
    def Get_All_User_Containers(self):
        '''

        :return: 返回所有的docker容器对象。组成一个list。
        '''

        try:
            Con_List = self.client.containers.list(all = True)
            logger.info('获取到所有容器对象。')
        except docker_errors.APIError as e :
            logger.warning('获取所有的容器对象失败，因为Docker服务出错！')
            return False
        return Con_List

    # 获取所有以某个镜像建立的容器
    def Get_All_Images_Containers(self, Images_Id):
        '''

        :param Images_Id: docker镜像的ID
        :return: 所有以某个docker镜像建立的容器对象，组成一个list。
        '''

        try:
            Con_List = self.client.containers.list(filters = {'ancestor' : Images_Id})
            logger.info('获取到所有ID为%s的镜像的容器对象。' % Images_Id)
        except docker_errors.APIError as e:
            logger.warning('获取所有ID为%s的镜像的容器对象。失败，因为Docker服务出错！' % Containers_Name)
            return False
        return Con_List

