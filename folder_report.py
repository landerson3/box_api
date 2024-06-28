import os, sys
sys.path.insert(0,os.path.expanduser('~'))
from box_api import box_api_class

def folder_report():
	if len(sys.argv) != 2:
		return
	else:
		box_id = sys.argv[1]
		box = box_api_class.box_api()
		files = box.get_folder_items(box_id)
		with open(os.path.expanduser(f'~/Desktop/box_report_{box_id}.csv'),'w') as csv:
			for f in files:
				csv.write(','.join(f.values())+'\n')

if __name__ == '__main__':
	folder_report()