#! coding=utf-8

'''
    实时获取系统的信息，包括cpu，IO，network，disk等。
    并提供接口给主服务。
'''

import psutil
import time


class Status():
    """获取系统信息！"""

    stu = {
        'Cpu_use': '', # cpu使用率 %
        'Io_ratio': '', # 内存使用率 %
        'Io_max': '', # 内存总大小 GB
        'Io_use': '', # 内存已使用 GB
        'Disk_ratio': '', # 磁盘使用率 %
        'Disk_max': '', # 磁盘总大小 GB
        'Disk_use': '', # 磁盘已使用 GB
        'Net_sent': '', # 上行网络
        'Net_recv': '' # 下行网络
    }

    def __init__(self):
        # 初始化时获取系统信息
        super(Status, self).__init__()
        self._Cpu()
        self._Io()
        self._Disk()
        self._Network()

    # 获取CPU的使用信息
    def _Cpu(self):
        c = psutil.cpu_times_percent(interval=1, percpu=False)
        self.stu['Cpu_use'] = '%.2f' % (100 - c.idle)
        # print('CPU使用率： %s' % ('%.2f' % (100 - c.idle) + '%'))

    # 内存的使用情况
    def _Io(self):
        i = psutil.virtual_memory()
        self.stu['Io_ratio'] = '%.2f' % i.percent
        self.stu['Io_max'] = '%.2fGB' % (i.total / 1024.0 / 1024.0 / 1024.0)
        self.stu['Io_use'] = '%.2fGB' % (i.used / 1024.0 / 1024.0 / 1024.0)
        # print ('内存使用率：%s\n内存总大小：%.2f MB\n内存使用：%.2f MB' % ('%.2f' % i.percent + '%',i.total/1024.0/1024.0,i.used/1024.0/1024.0))

    # 磁盘的使用情况
    def _Disk(self):
        d = psutil.disk_usage('/')
        self.stu['Disk_ratio'] = '%.2f' % d.percent
        self.stu['Disk_max'] = '%.2fGB' % (d.total / 1024.0 / 1024.0 / 1024.0)
        self.stu['Disk_use'] = '%.2fGB' % (d.used / 1024.0 / 1024.0 / 1024.0)
        # print ('硬盘使用率：%s\n硬盘总大小：%.2f GB\n硬盘使用：%.2f GB' % ('%.2f' % d.percent + '%',d.total/1024.0/1024.0/1024.0, d.used/1024.0/1024.0/1024.0))

    # 网络的使用情况
    def _Network(self):

        net1 = psutil.net_io_counters()

        time.sleep(2)

        net2 = psutil.net_io_counters()

        self.stu['Net_sent'] = '%s/s' % self.__bytes2human((net2.bytes_sent - net1.bytes_sent) / 2)
        self.stu['Net_recv'] = '%s/s' % self.__bytes2human((net2.bytes_recv - net1.bytes_recv) / 2)

    # 一个函数，把byte转换成K，M，G
    def __bytes2human(self, num):
        """
        bytes2human(10000)
        '9.8 K'
        bytes2human(100001221)
        '95.4 M'
        """
        symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
        prefix = {}
        for i, s in enumerate(symbols):
            prefix[s] = 1 << (i + 1) * 10
        for s in reversed(symbols):
            if num >= prefix[s]:
                value = float(num) / prefix[s]
                return '%.f%s' % (value, s)
        return '%.fB' % (num)

    def __del__(self):
        pass

# 开启一个while循环，获取系统信息到主进程
def Start_Get_Sysinfo(que):
    while 1 :
        s = Status()
        que.put(s.stu)
        time.sleep(10)


if __name__ == '__main__':

    start_time = time.time()
    s = Status()
    print(s.stu)
    end_time = time.time()

    print (end_time - start_time)