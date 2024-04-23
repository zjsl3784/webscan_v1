import subprocess
import requests
import time
import re
from scapy.all import *
from bs4 import BeautifulSoup



#########  Word List 기반 잘 알려진 관리자페이지 및 서버 디폴트 페이지 등 스캔 ##################
def check_url_existence(base_url, additional_paths):           
    """
    주어진 URL이 존재하는지 확인하는 함수
    """
    requests_count = 10     #타이머    
    requests_per_second = 5     #타이머
    interval = 1 / requests_per_second  #타이머
    
    urls_200 = []  # 200 응답 리스트
    urls_302 = []  # 302 응답 리스트
    urls_403 = []  # 403 응답 리스트
    urls_404 = []  # 404 응답 리스트
    urls_ano = []  # 기타 응답 리스트
    urls_chk = []  # 체크가 필요한 리스트
    serverinfo = [] # 서버정보 체크용

    print("웹 스캔 시작! (다소 시간이 소요될 수 있음)")
    try:
        for path in additional_paths:
            url = base_url + path

    # 로그인이 필요한 웹 사이트일 경우, 로그인 후 헤더값 입력 
            headers = {
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Chromium";v="123", "Not:A-Brand";v="8"',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Sec-Ch-Ua-Mobile': '?0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36',
    'Cookie': 'a'
}
            request = requests.Request('GET', url)
           # time.sleep(interval) #타이머
            prepared_request = request.prepare()
            
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                page_content = response.text
                if "404" in page_content or "페이지가 존재" in page_content or "에러" in page_content or "error" in page_content or "오류" in page_content:
                   if "not" in page_content and "found" in page_content:
                        urls_404.append(url)
                else:
                    urls_200.append(url)
                    urls_chk.append(url)
                
            elif response.status_code == 403:
                page_content = response.text
                if "404" in page_content or "페이지가 존재" in page_content or "에러" in page_content or "error" in page_content or "오류" in page_content:
                    urls_404.append(url)

                else:
                    urls_403.append(url)
                    urls_chk.append(url)
                    if "Apache" in page_content or "apache" in page_content or "IIS" in page_content or "iis" in page_content or "Nginx" in page_content or "nginx" in page_content or "Tomcat" in page_content or "tomcat" in page_content or "Jboss" in page_content or "jboss" in page_content or "WebLogic" in page_content or "weblogic" in page_content:
                        if not "URL" in page_content or "url" in page_content:
                            print(f"{url} 페이지에 서버정보로 의심되는 문자열이 포함됨.")
                            serverinfo.append(url)


            elif response.status_code == 302:
                page_content = response.text
                if "404" in page_content or "페이지가 존재" in page_content or "에러" in page_content or "error" in page_content or "오류" in page_content:
                    urls_404.append(url)
                else:
                    urls_302.append(url)
                    urls_chk.append(url)

                    
            elif response.status_code == 404:   # 404 응답을 받은 경우
                page_content = response.text
                #if "404" in page_content or "페이지가 존재" in page_content or "에러" in page_content or "error" in page_content or "오류" in page_content:
                urls_404.append(url)
                if "Apache" in page_content or "apache" in page_content or "IIS" in page_content or "iis" in page_content or "Nginx" in page_content or "nginx" in page_content or "Tomcat" in page_content or "tomcat" in page_content or "Jboss" in page_content or "jboss" in page_content or "WebLogic" in page_content or "weblogic" in page_content:
                    if not "URL" in page_content or "url" in page_content:
                        serverinfo.append(url)
                
            else:  
                urls_ano.append(url)        # 그외응답일 경우
                page_content = response.text
                if "Apache" in page_content or "apache" in page_content or "IIS" in page_content or "iis" in page_content or "Nginx" in page_content or "nginx" in page_content or "Tomcat" in page_content or "tomcat" in page_content or "Jboss" in page_content or "jboss" in page_content or "WebLogic" in page_content or "weblogic" in page_content:
                    if not "URL" in page_content or "url" in page_content:
                        serverinfo.append(url)



        print("웹 스캔 종료! END")
        print(" ")
     

        print("\n200 응답을 받은 URL:")
        for url_200 in urls_200:
            print(url_200)
            
        print(" ")

        print("\n302 응답을 받은 URL:")
        for url_302 in urls_302:
            print(url_302)
            
        print(" ")
        
        print("\n403 응답을 받은 URL:")
        for url_403 in urls_403:
            print(url_403)

        print(" ")
#        print("\n404 응답을 받은 URL:")       # 디버깅용
#        for url_404 in urls_404:
#            print(url_404)
#        print(" ")

        print("\n기타 응답을 받은 URL:")
        for url_ano in urls_ano:
            print(url_ano)
        print(" ") 

        print("디렉터리 인덱싱 의심항목 :")
        count1 = 0
        for urls_chk in urls_chk:
            response_chk = requests.get(urls_chk)
            page_content = response_chk.text
            if "index of" in page_content.lower():
                print(f"{urls_chk} 페이지에 'index of' 문자열이 포함됨.")
                count1 = +1
        if count1 < 1:
            print("의심항목이 없습니다.")                
        print(" ")
        
        print("서버정보 노출 의심항목 :")
        for serverinfo in serverinfo:
            print(f"{serverinfo} 페이지에 서버정보로 의심되는 문자열이 포함됨.")
        if not serverinfo:
            print("의심항목이 없습니다.")
        print(" ")                

    except Exception as e:
        print("오류 발생:", e)
    print(" ")

    print(" ")


########### 구글링 ###########################################
    googlestr1 = 'https://www.google.com/search?start=1&q=site%3A'
    googlechk1 = googlestr1 + base_url
    response = requests.get(googlechk1, headers=headers)

    if response.status_code == 200:
        print('구글링 요청이 성공했습니다.')
        print(" ")
        print('구글링 응답 내용:')
    
        # BeautifulSoup을 사용하여 HTML 파싱
        soup = BeautifulSoup(response.text, 'html.parser')
    
        # h3 태그에 해당하는 요소 추출
        h3_tags = soup.find_all('h3', class_='LC20lb')

        if not h3_tags:
            print("검색 결과가 없습니다.")
            print(" ")
    
        # 각 h3 태그의 텍스트 출력
        for h3_tag in h3_tags:
            print(h3_tag.text)
            print(" ")
    else:
        print('구글링 요청이 실패했습니다. 상태 코드:', response.status_code)

    googlestr2 = 'https://www.google.com/search?start=8&q=site%3A'
    googlechk2 = googlestr2 + base_url
    response = requests.get(googlechk2, headers=headers)

    if response.status_code == 200:
        # BeautifulSoup을 사용하여 HTML 파싱
        soup = BeautifulSoup(response.text, 'html.parser')
    
        # h3 태그에 해당하는 요소 추출
        h3_tags = soup.find_all('h3', class_='LC20lb')
    
        # 각 h3 태그의 텍스트 출력
        for h3_tag in h3_tags:
            print(h3_tag.text)
            print(" ")
    else:
        print('구글링 요청이 실패했습니다. 상태 코드:', response.status_code)
    print("종료 END")
##############################################################




######### Response 헤더 값 검사 ##############################
def get_server_info(base_url):
    try:
        response = requests.options(base_url)
        
        # 서버 헤더 가져오기
        server_header = response.headers.get('Server', 'N/A')
        powered_by_header = response.headers.get('X-Powered-By', 'N/A')
        
        return server_header, powered_by_header
    except Exception as e:
        print("Error:", e)
        return None, None

    if server_header and powered_by_header:
        print("Server:", server_header)
        print("X-Powered-By:", powered_by_header)
    else:
        print("서버 정보를 가져오는 데 문제가 있습니다.")

############################################################





############### Well-known 포트 SYN 스캐닝 #################

def syn_scan(base_url, ports):
    print("Well-known 포트들에 대한 SYN 스캔 시작! (시간이 소요될 수 있음)")
    portop = []
    portcl = []
    portfi = []
    host = re.search(r'(https?://)(.*?)(?:/|$)', base_url).group(2)
    try:
        for port in ports:
            # SYN 패킷 생성
            syn_packet = IP(dst=host) / TCP(dport=port, flags='S')
            
            # 패킷 전송 및 응답 대기
            response = sr1(syn_packet, timeout=3, verbose=False)
            
            # 응답 확인
            if response and response.haslayer(TCP):
                if response[TCP].flags == 18:  # SYN-ACK 응답 확인
                    portop.append(port)
                else:
                    portcl.append(port)
            else:
                portfi.append(port)


    except Exception as e:
        print(f"Error: {e}")
    print("Well-known 포트들에 대한 SYN 스캔 종료!")    
    print(" ")
    print("오픈 된 포트 목록:")
    if not portop:
        print("오픈 된 포트가 없음.")
    for port in portop:
        print(f"{port} port is Open!")
    print(" ")
      
########################################################################



###########   SSL/TLS 암호화 강도 검사   Nmap 설치 필요 ! ##############
    
def run_nmap_ssl_enum_ciphers(base_url):                #####
    host1 = re.search(r'(https?://)(.*?)(?:/|$)', base_url).group(2)
    try:
        # nmap 명령어 생성
        nmap_command = ["nmap", "--script", "ssl-enum-ciphers", host1]
        
        # nmap 실행 및 결과 얻기
        result = subprocess.run(nmap_command, capture_output=True, text=True)
        
        # 결과에서 ssl-enum-ciphers 부분 추출
        ssl_enum_ciphers_result = re.search(r'ssl-enum-ciphers:(.*)', result.stdout, re.DOTALL)
        
        # 결과 출력
        if ssl_enum_ciphers_result:
            #print(ssl_enum_ciphers_result.group(0))  # 전체 결과 출력
            print(ssl_enum_ciphers_result.group(1))  # 'ssl-enum-ciphers' 이후의 내용만 출력
        if not ssl_enum_ciphers_result:
            print("https 통신을 사용하지 않음.")
        
    except Exception as e:
        print("Error:", e)
        
#######################################################################


        


##### START #####
print("**************** webscan_psh_v1***************")
print(" ")
print("Made by 박수현")
print(" ")
print("Email : qkrtngus211@naver.com")
print(" ")
print("**********************************************")
print(" ")
print(" ")

print ("예시와 같이 스캔할 URL을 입력해 주세요. ")
print ("(예시 = https://test.com/ )")

print (" ")
base_url = input("입력 :")


# 웹스캔 WordList 선택       
with open("./List/List1.txt", "r") as file:  # WordList 파일 경로 지정       
    additional_paths = file.readlines()
additional_paths = [string.strip() for string in additional_paths]


print(" ")    
print("검사할 도메인 주소 ====>", base_url)
print(" ")
get_server_info(base_url)
server_header, powered_by_header = get_server_info(base_url)
print ("Response 값의 헤더 검사")
print("Server:", server_header)
print("X-Powered-By:", powered_by_header)

# 검사할 포트
ports = [80, 443, 22, 21, 20, 8080, 8443, 23, 24, 25, 37, 49, 53,
         79, 88, 109, 110, 111, 113, 123, 139, 143, 161, 162, 445, 514, 873,
         3306, 1194, 1080, 3479, 3480, 5228, 5353, 6379, 1331, 1293, 3389  ]

# 검사할 포트 파일로 받기
#with open("./List/portlist.txt", "r", encoding="utf-8") as file:   
#    ports = file.readlines()
#ports = [int(string.strip()) for string in ports]

print(" ")
print("SSL/TLS 암호화 강도 검사")
run_nmap_ssl_enum_ciphers(base_url)  # Nmap 설치 필요!
print(" ")
syn_scan(base_url, ports)
check_url_existence(base_url, additional_paths)


