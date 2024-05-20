import hashlib, base64, requests, json, os, time, secrets, jwt ## jwt must be installed with pip install PyJWT -- if standard jwt is installed, it must be removed
import threading, logging, time, datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

class Application_JSON_Error(Exception):
	"Raised when a 400 error is returned from Box"
	pass

class PermissionError(Exception):
	"Raised when a call has been made to a Box folder/asset outside for the API's permitted scope or the call is not allowed for the specified developer token"
	pass

# logging.basicConfig(filename = "BoxAPI.log",encoding = 'utf-8', format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level = logging.DEBUG)
# developer_token = 'nhXX4TIlsWA6XWqGnWhKnGh8N37hxHPP'
# client_id = '7rqp4gb50h2aipq8k24dwqkyyz9s5h2w'
# client_secret = 'o39MzUKKzJNtMrbbgVqvp4fGzd2X4mOt'
## Service Account = AutomationUser_1835368_z79ZTMNNm2@boxdevedition.com
class box_api():
	def __init__(self) -> None:
		logging.info('box_api_class.box_api() :: Initializing API')
		try:
			self.config = json.load(open('box_config.json'))
		except FileNotFoundError:
			self.config = json.load(open(os.path.expanduser('~/box_api/box_config.json')))
		logging.debug('box_api_class.box_api() :: Config loaded')
		self.max_threads = 100
		try:
			self.auth()
		except requests.exceptions.ConnectionError as cerr:
			logging.error(f'box_api_class.box_api().auth() :: {cerr}')
			return requests.exceptions.ConnectionError
		self.headers =  {
			'Authorization':f"Bearer {self.access_token}",
			'Content-Type' : 'application/json'
		}
		self.global_result = None
	
	def auth(self) -> None:
		logging.debug('box_api_class.box_api().auth() :: Authenticating API with config')
		appAuth = self.config["boxAppSettings"]["appAuth"]
		privateKey = appAuth["privateKey"]
		passphrase = appAuth["passphrase"]

		# https://cryptography.io/en/latest/
		key = load_pem_private_key(
		  data=privateKey.encode('utf8'),
		  password=passphrase.encode('utf8'),
		  backend=default_backend(),
		)

		authentication_url = 'https://api.box.com/oauth2/token'

		claims = {
		  'iss': self.config['boxAppSettings']['clientID'],
		  'sub': self.config['enterpriseID'],
		  'box_sub_type': 'enterprise',
		  'aud': authentication_url,
		  'jti': secrets.token_hex(64),
		  'exp': round(time.time()) + 45
		}
		keyId = self.config['boxAppSettings']['appAuth']['publicKeyID']
		assertion = jwt.encode(claims,key,algorithm='RS512',headers={'kid': keyId})

		params = {
		    'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
		    'assertion': assertion,
		    'client_id': self.config['boxAppSettings']['clientID'],
		    'client_secret': self.config['boxAppSettings']['clientSecret']
		}
		response = requests.post(authentication_url, params)
		self.access_token = response.json()['access_token']
		if hasattr(self,"authheaders"):
			self.authheaders['Authorization'] = f"Bearer {self.access_token}"
		if hasattr(self,"headers"):
			self.headers['Authorization'] = f"Bearer {self.access_token}"

		logging.info(f"box_api_class.box_api().auth() :: Authenticated with:\n\t{self.access_token}")
	
	def upload(self, files: str | list, destination: str) -> requests.Response:
		upload_url = "https://upload.box.com/api/2.0/files/content"
		# take a list of files (1-many) and a destination folder by URL or by ID
		# recurssive for lists of filesx
		if type(files) == list:
			logging.info(f'box_api_class.box_api().upload() :: list object found -- attempting to upload {len(files)} assets')
			for file in files:
				self.upload(file,destination)
			return
		logging.info(f"box_api_class.box_api().upload() :: Attempting to upload {files}")
		# if filesize is over 20000000 bytes (20mb), upload in chunks
		self.global_result = []
		# if filesize is less than 20000000 bytes (20mb), upload single file
		if not os.path.exists(files): return 0
		if os.path.getsize(files) > 20000000:
			try:
				session_response = self.create_upload_session(files,destination)
				if session_response.status_code == 409:
					return session_response
				logging.info('box_api_class.box_api().upload() :: Upload session created')
				_r = self.upload_as_chunk(files)
				# print(_r.status_code)
				if _r.status_code == 201 : self.global_result.append(files)
				logging.info('box_api_class.box_api().upload() :: Uploaded completed')
				# logging.debug(f'Uploaded completed with {_r.json()}')
			except KeyError as err: ## File upload already exists -- can add handling for this or ignore.
				logging.warning(f'box_api_class.box_api().upload() :: Failed to upload {files}')
				return KeyError
			except json.JSONDecodeError:
				self.upload(files, destination)
		else: ## process files less than 20mb
			file_name = os.path.basename(files)
			logging.debug(f"box_api_class.box_api().upload() :: Uploading file {file_name}")
			created_datetime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S-7:00")
			modified_datetime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S-7:00")
			binary_file = open(files,'rb')
			body = { 
				'attributes': json.dumps({
					'content_created_at': created_datetime,
					'content_modified_at': modified_datetime,
					'name': file_name,
					'parent':{'id':destination}
					})
			}
			headers = self.headers
			if 'Content-Type' in headers:
				del headers['Content-Type']
			_r = requests.post(upload_url, headers = headers, data = body, files = {'file':binary_file})
			logging.debug(f"box_api_class.box_api().upload() :: {file_name} uploaded to Box folder {destination} with values\n{body}\nand response\n{_r.status_code}\n{_r.content}")
			## end of the sub-20mb section
		return _r
	
	def upload_preflight(self, file: str, destination: str) -> requests.Response:
		# https://developer.box.com/reference/options-files-content/
		url = 'https://api.box.com/2.0/files/content'
		data = json.dumps({
			'name': os.path.basename(file),
			'parent': {'id':str(destination)},
			'size': os.path.getsize(file),
		})
		response = requests.options(url, headers=self.headers, data = data)
		# print(response)
		# print(response.content)
		# print(response.headers)
		return response.status_code

	def create_upload_session(self, file: str, folder_id: int) -> requests.Response:
		self.authheaders = {
			'Authorization':f"Bearer {self.access_token}",
			'Content-Type' : 'application/json'
		}
		data = {
			'folder_id': str(folder_id),
			'file_size': os.path.getsize(file),
			'file_name': os.path.basename(file)
		}
		r = requests.post('https://upload.box.com/api/2.0/files/upload_sessions', 
			headers = self.authheaders, json = data)
		if r.status_code == 401: 
			self.auth()
			r = requests.post('https://upload.box.com/api/2.0/files/upload_sessions', 
		     headers = self.authheaders, json = data)
		self.upload_session = r.json()
		
		return r
		# logging.info(f"Uploading :: {file} to {folder_id}")

	def upload_chunk(self, bytes_chunk: str|bytes, headers: dict, session_id: str|int, brange: tuple|list, attempts = 0) -> requests.Response|None:
		# upload a chunk of a file
		# check that the offset isn't already in the parts_to_comit
		rest_time = (attempts * 2)*.25
		time.sleep(rest_time)
		attempts +=1
		if attempts >= 10: return None
		for i in self.total_parts_to_commit:
			if i['offset'] == brange[0]: break
		else:
			self.total_parts_to_commit.append(
				{
					"part_id": None,
					"offset":brange[0],
					"size": len(bytes_chunk)
				})
		try:
			r = requests.put(f'https://upload.box.com/api/2.0/files/upload_sessions/{session_id}', 
				headers = headers, data = bytes_chunk, timeout = 120)
			if r.status_code == 500:
				r = self.upload_chunk(bytes_chunk, headers, session_id, brange)
				# r = self.upload_chunk(bytes_chunk, headers, session_id, brange)
		except (ConnectionResetError,requests.exceptions.ConnectionError, json.decoder.JSONDecodeError) as err:
			r = self.upload_chunk(bytes_chunk,headers,session_id,brange,attempts=attempts)					
		logging.debug(f"box_api.upload_chunk() :: response evaluated with 'r' value of {r}")
		if r == None: return None
		if r.status_code >300:
			pass
		for i in self.total_parts_to_commit:
			if "part" not in r.json() or "part_id" not in r.json()['part']:
				continue
			if i['offset'] != brange[0]:continue
			else:
				logging.debug(f"box_api.upload_chunk() :: Attempting to append partID to offset {i['offset']}. Json:: \n\t{r.json()}")
				i['part_id'] = r.json()['part']['part_id']
		# c_range = headers['content-range']
		return r
		# print(f'Content Range: {c_range}',flush = True)
		# print(r.content,"\n",flush = True)
		
	def upload_as_chunk(self, file: str) -> requests.Response:
		'''Uploads the total file (calls upload_chunk for each chunk of the file)'''
		self.total_parts_to_commit = []
		chunk_size = self.upload_session['part_size']
		total_parts = self.upload_session['total_parts']
		session_id = self.upload_session['id']
		# total_parts_to_commit = []
		logging.debug(f'''Chunk Upload for {file} ::\n
			\tChunk size : {chunk_size}\n
			\tTotal Parts : {total_parts}\n
			\tSession ID : {session_id}''')
		## determine if the "file" is a path or a byte object
		if type(file) != bytes and os.path.exists(file): 
			self.bfile = open(file,'rb').read()
		else:
			self.bfile = bytes(file)
		logging.debug('Byte file opened and read')
		file_size = os.path.getsize(file)
		chunk_threads = []
		for part in range(int(total_parts)):
			chunk_threads.append(self.chunk_driver(part, file_size))
		## commit the session
		commit_headers = self.authheaders ## need to build this out still
		commit_headers['Digest']= str("sha="+base64.b64encode(hashlib.sha1(self.bfile).digest()).decode('utf-8'))
		
		count_active_chunk_uploads = lambda cthds: len([t for t in cthds if t.is_alive()])		
		while count_active_chunk_uploads(chunk_threads):
			continue

		
		r = self.commit_session(commit_headers, file_size)

		logging.debug(r)
		try: logging.debug(r.json())
		except: pass
		return r
	
	def parts_null(self) -> bool:
		for i in self.total_parts_to_commit:
			if i['part_id'] == None: return True
		else:
			return False
	
	def chunk_driver(self, part: int|str, file_size: str|int) -> None:
		chunk_size = self.upload_session['part_size']
		total_parts = self.upload_session['total_parts']
		session_id = self.upload_session['id']
		logging.debug(f'Uploading part {part} of {total_parts}')
		brange = (part*chunk_size, (part+1)*chunk_size)
		bytes_chunk = self.bfile[brange[0]:brange[1]]
		digest = base64.b64encode(hashlib.sha1(bytes_chunk).digest())
		## calculate the content range
		if brange[0] == 0 : 
			start, end = 0, chunk_size-1
		else: 
			start,end = brange[0], brange[0]+len(bytes_chunk)-1
		headers = self.authheaders
		headers['content-range'] = str(f"bytes {start}-{end}/{file_size}")
		headers['digest'] = str('sha='+digest.decode('utf-8'))
		# print(part,flush=True)
		while threading.active_count()>self.max_threads: continue ## limit threads
		t = threading.Thread(target = self.upload_chunk, args = (bytes_chunk,headers,session_id, brange))
		t.start()
		return t
		
		# self.upload_chunk(bytes_chunk,headers,session_id, brange)
	
	
	## to do - add handling for commits that hang. How can we move onto the next upload while the commit is processing?
	def commit_session(self, headers: dict, file_size: str|int, attempts: int = 0) -> requests.Response:
		# this should create a sorted list of offsets and parts for the commit
		d = sorted(self.total_parts_to_commit, key = lambda x: x['offset'])
		_json = {"parts":d}
		commit = self.upload_session['session_endpoints']['commit']
		r = requests.post(commit, headers = headers, json = _json )
		while r.status_code == 202 and attempts < 20:
			# print(time.time())
			time.sleep(attempts)
			attempts+=1
			r = requests.post(commit, headers = headers, json = _json )
		# handle unwanted status codes
		if  r.status_code > 300:
			if r.status_code == 401:
				self.auth()
				r = self.commit_session(headers, file_size)
			if (r.status_code == 400 and not self.parts_null()) or r.status_code == 503:
				while self.parts_null():
				# reupload the failed chunks 
					for i,j in enumerate(self.total_parts_to_commit):
						if j['part_id'] == None:
							self.chunk_driver(i,file_size)
				r = self.commit_session(headers, file_size)
			else:
				pass
		return r
		
	def get_file_info(self,file_id: str|int, *_params) -> dict:
		if type(file_id) == list and type(file_id[0] ) == dict: file_id = file_id[0]['id']
		if _params != None and _params != ():
			r = requests.get(f'https://api.box.com/2.0/files/{file_id}',headers = self.headers, params = _params[0])
		else:
			r = requests.get(f'https://api.box.com/2.0/files/{file_id}',headers = self.headers)
		if r.status_code == 401:
			self.auth()
			r = requests.get(f'https://api.box.com/2.0/files/{file_id}',headers = self.headers)
		# logging.debug(f"box_api_class.box_api().get_file_info({file_id}) :: returned with status {r}\n\tand content {r.content}")
		return r.json()

	def get_file_path(self, file_id: int|str) -> str:
		info = self.get_file_info(file_id)
		path = ''
		# print(info['path_collection'], flush = True)
		if 'path_collection' not in info:
			return None
		for entry in info['path_collection']['entries']:
			path = path + f"{entry['name']}/"
		path = path + info['name']
		return path
	
	def path_collection_to_path(self,path_collection: dict) -> str:
		res = "/"
		for i in path_collection['entries']:
			res = res+f"{i['name']}/"
		return res
	
	def get_folder_items(self, folder_id: str|int, include_subfolders:bool = True, offset:int = 0, limit:int = 1000, exclusions:str|list|tuple = None, previous_res = None) -> list:
		''' 
		Takes a folder ID and recursively return all assets from all subfolders if desired
		folder_id - string/integer of the folder_ID to sort
		include_subfolders - if true, report on all subfolders
		offset - for folders with more than 1000 items, we need multiple requests
		limit - default 1000 as the maximum number of assets to return at once
		exclusions - string/int/list of folder IDs to exclude from the report
		'''
		# print(f"Getting assets from folderID {folder_id} with offset of {offset}", flush = True)
		if exclusions != None:
			if type(exclusions) == str: exclusions = list(exclusions)
			if (folder_id == exclusions or folder_id in exclusions): return
		data = {
			"offset":int(offset),
			"limit":int(limit)
		}
		response = requests.get(f'https://api.box.com/2.0/folders/{folder_id}/items', headers = self.headers, params = data)
		limiter = 0
		while response.status_code == 503 and limiter < 20:
			time.sleep(1) 
			response = requests.get(f'https://api.box.com/2.0/folders/{folder_id}/items', headers = self.headers, params = data)
		try:
			response_json = response.json()
		except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError) as JSONerr:
			logging.error(f"box_api_class.box_api().get_folder_items({folder_id}) :: {JSONerr}")
			# print(f"Error processing: {folder_id}",flush = True)
			return
		entries = response_json['entries']
		# if offset == 0: self.global_result == []
		if None in [self.global_result, previous_res]: self.global_result = []
		
			# build the current folder path for appending names from entries
		folder_info = self.get_folder_information(folder_id)
		if folder_info != None:
			path = self.path_collection_to_path(folder_info['path_collection'])
		elif folder_info == None: path = f"Error generating path for {folder_id}"
		for entry in entries:
			if include_subfolders:
				if entry['type'] == "folder" and entry['id'] not in exclusions: self.get_folder_items(entry['id'],True, exclusions=exclusions, previous_res=self.global_result) # recursion
			# allow the exclusions parameter to contain 'folder' 
   				# and 'file' so we can get just the folders or just the files in a directory
			if entry['type'] in exclusions: continue
			res = {
				'name':entry['name'],
				'path':f"{path}{folder_info['name']}/{entry['name']}", ## return the box bath in the format of ".../.../.../file.ext"
				'id':entry['id']
				}
			if 'sha1' in entry: res['sha1'] = entry['sha1']
			if 'parent' in entry: res['parent'] = entry['parent']
			self.global_result.append(res)
		if len(entries) >= 1000:
			offset = int(response_json['offset'])+len(entries)
			self.get_folder_items(folder_id,include_subfolders,offset)		
		return self.global_result
	
	def download_chunk(self, file_id: str|int, _range: str) -> None: ## expect the _range to be like f"bytes={download_range[0]}-{download_range[1]}""
		headers = self.headers
		headers['range'] = _range
		logging.debug(f'box_api_class.box_api().download_chunk({file_id}) :: Attempting to download chunk : {_range}')
		try:
			r = requests.get(f'https://api.box.com/2.0/files/{file_id}/content',headers = headers)
			if r.status_code == 401:
				self.auth()
				self.download_chunk(file_id, _range)
				return
		except requests.exceptions.ReadTimeout:
			logging.error('Request for chunk download timed out.')
			return requests.exceptions.ReadTimeout
		for i in self.total_download_parts:
			if i['chunk'] == int(_range.replace('bytes=',"").split('-')[0]):
				i['content'] = r.content
		

	def get_folder_information(self, folder_id: str|int) -> dict:
		response = requests.get(f'https://api.box.com/2.0/folders/{folder_id}', headers = self.headers)
		if response.status_code != 200: return None
		return response.json()

	def download_files(self, files: list|str, destination:str = os.path.expanduser("~/Downloads/Box_Downloads/"), **kwargs) -> str:
		logging.debug(f"box_api_class.box_api().download_files() :: {type(files)}")
		if 'version' in kwargs: version = kwargs['version']
		else: version = None

		# recursive for lists
		if type(files) == type(list()):
			logging.debug("box_api_class.box_api().download_files() :: called with list; running recursively")
			for file in files:
				# self.download_files(file,destination, version = version)
				sub_result = self.download_files(file,destination, version = version)
				return sub_result
		if type(files) == type(dict()) and "id" in files:
			files = files['id']
		if self.item_type(files) == "folder":
			files = self.get_folder_items(files)
			for file in files:
				self.download_files(file,destination)
			
		# make destination path as needed
		if "~" in destination: destination = os.path.expanduser(destination)		
		if "Volumes" not in destination and not (os.path.isdir(os.path.dirname(destination)) or os.path.exists(destination)):
			if destination[0] == '/': destination = f'/Volumes{destination}'
			else: destination = f"/Volumes/{destination}"
		destination = destination.replace(":","/")
		if not os.path.isdir(os.path.dirname(destination)):
			logging.info(f"box_api_class.box_api().download_files() :: Making directory {os.path.dirname(destination)}")
			if not os.path.exists(os.path.dirname(destination)):
				os.mkdir(os.path.dirname(destination))
		logging.info(f'box_api_class.box_api().download_files() :: Downloading file {files} to {destination}')
		
		# limit for maximum threads
		while threading.active_count()>self.max_threads: 
			logging.debug(f'box_api_class.box_api().download_files() :: Maximum thread count of {self.max_threads} exceded while downloading {files}')
			continue

		#establish filesize for chunking
		file_info = self.get_file_info(files)
		self.download_file_size = file_info['size']
		file_name = file_info['name']

		# break downloads up by the number of allowable threads and download
		# self.download_chunk_size = round(self.download_file_size / (self.max_threads))
		self.download_chunk_size = round(self.download_file_size / 4)
		# self.download_chunk_size = 1024

		logging.debug(f"box_api_class.box_api().download_files() :: Downloading chunk sizes : {self.download_chunk_size}")
		# self.download_contents = b''
		self.total_download_parts = []
		if not os.path.isdir(destination): destination = os.path.dirname(destination)
		for chunk in range(0,self.download_file_size,self.download_chunk_size):
			logging.debug(f"Box_api().download_files :: Downloading chunk {chunk} of {self.download_file_size} with chunk sizes of {self.download_chunk_size}")
			self.total_download_parts.append({'chunk':chunk,'content':b''})
			range_string = self.calculate_range_string(chunk)
			self.download_chunk(files,range_string)
			# threading.Thread(target=self.download_chunk, args = (files,range_string)).start()

		

		while self.null_parts_download():
			for i in self.total_download_parts:
				if i['content'] in [None, b'', ''] or type(i['content']) == dict:
					self.download_chunk(files, self.calculate_range_string(i['chunk']))

		self.total_download_parts = sorted(self.total_download_parts, key = lambda x: x['chunk'])
		download_contents = b''
		download_contents = download_contents.join([i['content'] for i in self.total_download_parts ])
		destination_file = os.path.join(destination,file_name)
		if os.path.exists(destination_file): os.remove(destination_file)
		time.sleep(.25)
		logging.debug(f"Attempting to create file {destination_file}")
		# check that the download is complete
		initial_threads = threading.active_count()
		while threading.active_count() > initial_threads+1: continue
		# threading.Thread(target = self.write_output, args = (destination_file, download_contents)).start()
		self.write_output(destination_file, download_contents)
		return destination_file
	
	def write_output(self, destination_file: str, download_contents: bytes) -> None:
		with open(destination_file,'wb') as d_file:
			logging.debug(f"Writing file {destination_file}")
			d_file.write(download_contents)

	def generate_sha(self, file:str) -> str:
		with open(file, "rb").read() as f:
			return hashlib.sha1(f).hexdigest()

	def null_parts_download(self) -> bool:
		for i in self.total_download_parts:
			if i['content'] in [None, b'', ''] or type(i['content']) == dict:
				return True
		else:
			return False
			
	def calculate_range_string(self, chunk: int) -> str:
		bytes_start = chunk
		bytes_end = chunk + self.download_chunk_size
		if bytes_end > self.download_file_size or self.download_file_size-self.download_chunk_size < bytes_end:
			bytes_end = self.download_file_size
		download_range = (bytes_start,bytes_end-1)
		range_string = f"bytes={download_range[0]}-{download_range[1]}"
		return range_string


	def item_type(self, id: int|str) -> str|None:
		try:
			if requests.get(f"https://api.box.com/2.0/files/{id}", headers=self.headers).status_code == 200:
				return "file"
			elif requests.get(f"https://api.box.com/2.0/folders/{id}", headers=self.headers).status_code == 200:
				return "folder"
		except:
			pass
		return None

	def download_as_zip(self, assetID, destination = os.path.expanduser("~/Downloads/Box_Downloads/")):
		# process a list of assetIDs to the xip_downloads endpoint
		# https://developer.box.com/reference/post-zip-downloads/
		if type(assetID) != list:
			assetID = list(assetID)
		pass

	def search(self, params, max_return = None):
		if params is None or params == {}:
			raise ValueError("No value provided for params in box_api.search()")
		if "limit" not in params or params['limit']>200:
			params['limit'] = 200
		response = requests.get("https://api.box.com/2.0/search",headers = self.headers, params = params )
		if response.status_code == 400:
			return []
			# raise Application_JSON_Error
		elif response.status_code in (403,404):
			raise PermissionError
		elif response.status_code != 200:
			return []
			# raise Exception("An unexpected error occured")
		else: ## parse the response and return results
			r = response.json()
			# print(r)
			if "entries" not in r: raise ValueError(f"'Entires' not found in {r}")
			if len(r['entries']) + r['offset'] < r["total_count"] and (max_return is not None and len(r['entries']) < len(r['entries']) < max_return):
				params['offset'] = len(r['entries']) + r['offset']
				self.search(params)
		return r['entries']
				
	def search_filename(self, filename, *folder):
		p = {
			"type" : "file",
			"content_types" : ["name"],
			"query" : '"'+filename+'"'
		}
		if folder is not None:
			if type(folder) != type(list()): folder = [folder]
			p['ancestor_folder_ids']=folder
		return self.search(p)

	def create_folder(self, parent_id=0, name="new_folder") -> str:
		logging.debug(f"Creating folder {name} in parent {parent_id}")
		url = "https://api.box.com/2.0/folders"
		headers = self.headers
		data = json.dumps({
			'name':name,
			'parent':{'id':parent_id}
		})
		r = requests.post(url, data=data, headers = headers)
		## return the folder id if it exists or return None

		if r.status_code == 201:
			logging.debug(f'Succesfully created folder')
			return str(r.json()['id'])
		elif r.status_code == 409 and r.json()['code'] == "item_name_in_use":
			res = r.json()['context_info']['conflicts'][0]['id']
			logging.debug(f"Folder exists, returning {res}")
			return res
		else:
			logging.error(f"Could not create folder. Result of {r}")
			return None
		# except:
		# 	return None

	def move_file(self, file_id: str|int, parent_id:str|int):
		url = f'https://api.box.com/2.0/files/{file_id}'
		headers = self.headers
		data = json.dumps({
			'parent':{'id':parent_id}
		})
		r = requests.put(url, data=data, headers = headers)
		if r.status_code == 201:
			logging.debug(f"Succesfully copied file: {r}, new file ID: {r.json()['id']}")
			return r.json()['id']
		else:
			logging.error(f"Could not move file: {r}")
			return None

	def copy_file(self, file_id, parent_id):
		url = f"https://api.box.com/2.0/files/{file_id}/copy"
		headers = self.headers
		data = json.dumps({
			'parent':{'id':parent_id}
		})

		r = requests.post(url, data=data, headers = headers)

		if r.status_code == 201:
			logging.debug(f"Succesfully copied file: {r}, new file ID: {r.json()['id']}")
			return r.json()['id']
		else:
			logging.error(f"Could not move file: {r}")
			return None

	def delete_file(self, file_id):
		logging.debug(f'Deleting file: {file_id}')
		url = f"https://api.box.com/2.0/files/{file_id}"
		headers = self.headers

		r = requests.post(url, headers = headers)

		if r.status_code == 204:
			logging.debug(f'Succesfully deleted file: {r}')
			return r
		else:
			logging.error(f"Could not delete file: {r}")
			return None

	def get_sha(self, file_id: str) -> str:
		if type(file_id) == type(list()):
			self.global_result = []
			for i in file_id: 
				self.get_sha(i)
		
		r = requests.get(f"https://api.box.com/2.0/files/{file_id}", headers = self.headers)
		if r.status_code == 200:
			return r.json()['file_version']['sha1']
		# try: self.global_result.append(r.json()['file_version']['sha1'])
		# except:
		# 	self.global_result.append("ERROR")
		# return self.global_result

	def create_shared_link(self, file_id: str|int, body: dict) -> str:
		r = requests.put(f'https://api.box.com/2.0/files/{str(file_id)}?fields=shared_link',headers = self.headers, data = body)
		if r.status_code == 200:
			# params = {'fields': 'shared_link'}
			r = self.get_file_info(file_id)
			

			return r
		
	# Get shared link for file

# b = box_api()
# b.download_files('1229860044402')