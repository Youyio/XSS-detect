import re
import numpy as np
from sklearn import model_selection
from sklearn import datasets
from sklearn import svm
from sklearn.externals import  joblib
from sklearn.metrics import classification_report
from sklearn import metrics
import pandas as pd

df = pd.read_csv("deep-xss/data.csv")
#df=df.sample(frac=1)
df = df.sample(frac=1).reset_index(drop=True)
df.head()

len(df)

featureSet = pd.DataFrame(columns=('payload','script','alert','LeftBracket','RightBracket',\
'%','isPresentDSlash','SubDir','(',')','lable'))

def countscript(payload):
    return payload.lower().count('script')

def countalert(payload):
    return payload.lower().count('alert')

def countLeftBracket(payload):
    return payload.count('<')

def countRightBracket(payload):
    return payload.count('>')

def countpercent(payload):
    return payload.count('%')

def isPresentDSlash(payload):
    return payload.count('\"')

def countSubDir(payload):
    return payload.count('\'')

def countLeft(payload):
    return payload.count('(')

def countRight(payload):
    return payload.count(')')
    
    

def getFeature(payload,lable):
    fea = []
    payload = str(payload)
        
    fea.append(payload)
    fea.append(countscript(payload))
    fea.append(countalert(payload))   
    fea.append(countLeftBracket(payload))
    fea.append(countRightBracket(payload))
    fea.append(countpercent(payload))
    fea.append(isPresentDSlash(payload))
    fea.append(countSubDir(payload))
    fea.append(countLeft(payload))
    fea.append(countRight(payload))
    fea.append(str(lable))
    
    return fea


for i in range(len(df)):
    features = getFeature(df["param"].loc[i],df["lable"].loc[i])
    featureSet.loc[i] = features
    
    
featureSet.head()

featureSet.to_csv("deep-xss/features.csv",index=False)

len(featureSet)

featureSet.groupby(featureSet['lable']).size()

X = featureSet.drop(['payload','lable'],axis=1).values
y = featureSet['lable'].values

X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, y ,test_size=0.3)

import pandas as pd
from sklearn import tree,cross_validation
import sklearn.ensemble as ek
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix


model = { "DecisionTree":tree.DecisionTreeClassifier(max_depth=10),
         "RandomForest":ek.RandomForestClassifier(n_estimators=50),
         "Adaboost":ek.AdaBoostClassifier(n_estimators=50),
         "GradientBoosting":ek.GradientBoostingClassifier(n_estimators=50),
         "GNB":GaussianNB(),
         "LogisticRegression":LogisticRegression()   
}


#测试不同算法的准确度
results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score_test = clf.score(X_test,y_test)
    score_train = clf.score(X_train,y_train)
    print ("%s : %s %s" %(algo, score_test,score_train))
    results[algo] = score_test
    
    
   
print(results)


winner = max(results, key=results.get)
print(winner)


clf = model[winner]
res = clf.predict(X_test)
mt = confusion_matrix(y_test, res)#混淆矩阵
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))


from sklearn.metrics import accuracy_score, precision_score, recall_score


#准确率 = 分类正确的样本数/总样本数
accuracy_score(y_test, res)


result = pd.DataFrame(columns=('payload','script','alert','LeftBracket','RightBracket',\
'%','isPresentDSlash','SubDir','(',')','lable'))

results = getFeature('Itemid=%22onmouseover=alert%28document.cookie%29%20bad=%22', '1')
result.loc[0] = results
result = result.drop(['payload','lable'],axis=1).values
print(clf.predict(result))


