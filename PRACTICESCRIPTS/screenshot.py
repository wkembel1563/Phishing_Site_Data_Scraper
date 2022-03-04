from selenium import webdriver
from PIL import Image

try:
	driver = webdriver.Chrome('/home/kaifeng/chrome_driver')
	
except Exception as e:
	print('Exception. driver setup failed')



