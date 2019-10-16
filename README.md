# 实验环境

- sklearn、pandas、numpy
- deep-xss数据集

# 实验内容

- 本实验中，将deep-xss中的数据进行整理之后，集中到data.csv

- 选取特征

  ```
  featureSet = pd.DataFrame(columns=('payload','script','alert','<','>',\
  '%','\"','\'','(',')','lable'))
  ```

- 采用随机森林

- 准确率可达：98.28%

# 预测方式

在最后一段代码中直接修改getFeature()函数中的传参即可

