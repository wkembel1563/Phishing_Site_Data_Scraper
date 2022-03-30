import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def take_screenshot(iteration,url,filename):

	options = webdriver.ChromeOptions()
	options.headless = True
	#driver = webdriver.Chrome(options=options)
	driver = webdriver.Chrome(executable_path='/home/sayaksr/Desktop/chromedriver/chromedriver',options=options)

	URL = url

	driver.get(URL)

	time.sleep(3)

	S = lambda X: driver.execute_script('return document.body.parentNode.scroll'+X)
	driver.set_window_size(S('Width'),S('Height')) # May need manual adjustment                                                                                                                
	#driver.find_element_by_tag_name('body').screenshot('screens/'+str(iteration)+"/"+str(filename)+'.png') OLD USAGE
	driver.find_element_by_tag_name('body').screenshot('screens/'+str(iteration)+"/"+str(filename)+'.png')


	driver.quit()