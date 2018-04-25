#! coding=utf-8
import logging

logger = logging.getLogger()  # 不加名称设置root logger
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                              datefmt = '%Y-%m-%d %H:%M:%S'
                    )

# 使用FileHandler输出到文件
File_log = logging.FileHandler('./log/app_info.log', 'r+')
File_log.setLevel(logging.INFO)
File_log.setFormatter(formatter)

# 使用StreamHandler输出到屏幕
Terminal_log = logging.StreamHandler()
Terminal_log.setLevel(logging.INFO)
Terminal_log.setFormatter(formatter)

# 添加两个Handler
logger.addHandler(Terminal_log)
logger.addHandler(File_log)
