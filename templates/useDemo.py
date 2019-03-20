import requests




files = {'file': open('../pdfm/hetong.pdf', 'rb')}
url = 'http://pdf.simplified.org.cn:3000/api/vbeta'

# use api
r = requests.post(url, files=files,auth=('miguel', 'python'))

# return result
print (r.status_code) # 200: success 
print (r.encoding)


# save file 
f = open('output.csv','w')
encoding = 'utf-8' #'gbk'
f.write(r.text.encode( encoding ))
f.close()
