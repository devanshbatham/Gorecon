package main
import (
	"fmt"
	"github.com/fatih/color"
	"github.com/likexian/whois-go"
	"io/ioutil"
	"os"
	"io"
	"flag"
	"net"
	"net/http"
    "log"
    "time"
	"bufio"
	"github.com/gocolly/colly"
    "strings"
    "os/exec"
    "runtime"
)
func main(){
//	var port int
	var banner  = ` 
	██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
	██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
	██║  ███╗██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
	██║   ██║██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
	╚██████╔╝╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
	 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
`
color.Red("%s",banner)
color.Cyan("             coded with <3 by Devansh Batham ")
url := flag.String("url", "u", "-url")
flag.Parse()
if(*url != "u"){
color.Green("Entered Url is : ")
fmt.Print(*url)
color.Yellow("\nOptions available : \n")
color.Yellow( "1  - [+] Dns Lookup " )
color.Yellow( "2  - [+] Whois Lookup ")
color.Yellow( "3  - [+] Nmap scan ")
color.Yellow( "4  - [+] Zone Transfer Lookup ")
color.Yellow( "5  - [+] Shared DNS server lookup")
color.Yellow( "6  - [+] Web Crawler ")
color.Yellow( "7  - [+] Reverse DNS lookup")
color.Yellow( "8  - [+] Subnet calculator")
color.Yellow( "9  - [+] Admin panel finder (with Screenshots)")
color.Yellow( "10 - [+] Directory Bruteforce (with Screenshots)")
color.Yellow( "11 - [+] Configuration Files Finder")
color.Yellow( "12 - [+] HTTP Header Information") // todo - > Implementing check for misconfigured headers 
color.Yellow( "13 - [+] GeoIp Lookup")
color.Yellow( "14 - [+] Find/Analyze Content Management System (CMS) ")
color.Yellow( "15 - [+] Email Hunter (find emails of the company)")
color.Yellow( "16 - [+] Use Rapid7 Open Data's Project Sonar for Finding Subdomains)")
color.Yellow( "17 - [+] Use Virustotal API for Finding subdomains")
color.Yellow( "18 - [+] Use Threatcrowd's API for Finding subdomains")
color.Yellow( "19 - [+] Run all Scans")

var ch int
color.Green("Enter your choice : ")
fmt.Scanf("%d",&ch)
if (ch == 1){// if choice is 1 
domainlookup(*url)//calling domainlookup function -- > performs dns lookup 
}else if(ch == 2){ // if choice is 2 
whoislookup(*url)// calling whois function -- > performs whois of domain
}else if ( ch == 3) {// if choice is 3 
shownmap(*url) //calling shownmap function -- > performs nmap scan 
}else if (ch == 4) { //if choice is 4 
showzone(*url) // calling showzone function -- > performs zone transfer lookup 
}else if (ch == 5){//if choice is 5 
	shareddns(*url) //calling function shareddns -- > performs shared dns lookup
}else if (ch == 6){ // if choice is 6 
	extractlinks(*url) // calling fucntion extractlinks -- > extracts all links on webpage
}else if (ch == 7){ // if choice is 7 
	reversedns(*url) // calling reversedns -- > performs reverse dns lookup
}else if (ch == 8) { // if choice is 8 
	subnet(*url ) // calling subnet function -- > calculates subnet 
}else if(ch == 9){ // if choice is 9 
	adminpanel(*url) // calling adminpanel  function -- > bruteforces admin panel paths  
}else if (ch == 10){
	dirbrute(*url)
}else if (ch == 11){
	conffile(*url)
}else if(ch == 12) {
	getheader(*url)
}else if (ch == 13){
	geoip(*url)
}else if(ch == 14){
	getcms(*url)
}else if(ch == 15){
	emailhunter(*url)
}else if(ch==16){
   opendata(*url)
}else if(ch==17){
 virustotal(*url)
}else if(ch == 18){
threatcrowd(*url)
}else if (ch == 19){
    color.Green("Want to run 9,10,11 also ?? (y/n)")
    var choice string
    fmt.Scanf("%s",&choice)
    fmt.Scanf("%s",&choice)
    if(choice == "y" || choice == "Y"){
	color.Cyan("[!] Domain Lookup results : ")
	domainlookup(*url)
	color.Cyan("\n[!] Whois Lookup results : ")
	whoislookup(*url)
	color.Cyan("\n[!] NMAP Scan results : ")
	shownmap(*url)
	color.Cyan("\n[!] Zone Transfer Lookup results : ")
	showzone(*url)
	color.Cyan("\n[!] Shared DNS Lookup results : ")
	shareddns(*url)
	color.Cyan("\n[!] All Links Present On Webpage : ")
	extractlinks(*url)
	color.Cyan("\n[!] Reverse DNS Lookup results : ")
	reversedns(*url)
	color.Cyan("\n[!] Calculated Subnet results : ")
    subnet(*url )
    color.Cyan("\n[!] Bruteforcing Admin Panel : ")
    adminpanel(*url)
    color.Cyan("\n[!] Bruteforcing Directories :  ")
    dirbrute(*url)
    color.Cyan("\n[!] Bruteforcing Configuration File :  ")
    conffile(*url)
	color.Cyan("\n[!] HTTP header results : ")
    getheader(*url)
    color.Cyan("\n[!] GeoIP Information : ")
    geoip(*url)
    color.Cyan("\n[!] CMS Information :")
    getcms(*url)
    color.Cyan("\n[!] Searching for Emails : ")
    emailhunter(*url)
    color.Cyan("\n[!] Identified  Subdomains : ")
    opendata(*url)
    color.Cyan("\n[!] Making connection with virustotal : ")
    virustotal(*url)
    color.Cyan("\n [!] Making connection with Threatcrowd : ")
    threatcrowd(*url)
    }else if(choice == "n" || choice == "N"){
    color.Cyan("[!] Domain Lookup results : ")
	domainlookup(*url)
	color.Cyan("\n[!] Whois Lookup results : ")
	whoislookup(*url)
	color.Cyan("\n[!] NMAP Scan results : ")
	shownmap(*url)
	color.Cyan("\n[!] Zone Transfer Lookup results : ")
	showzone(*url)
	color.Cyan("\n[!] Shared DNS Lookup results : ")
	shareddns(*url)
	color.Cyan("\n[!] All Links Present On Webpage : ")
	extractlinks(*url)
	color.Cyan("\n[!] Reverse DNS Lookup results : ")
	reversedns(*url)
	color.Cyan("\n[!] Calculated Subnet results : ")
	subnet(*url )
	color.Cyan("\n[!] HTTP header results : ")
    getheader(*url)
    color.Cyan("\n[!] GeoIP Information : ")
    geoip(*url)
    color.Cyan("\n[!] CMS Information :")
    getcms(*url)
    color.Cyan("\n[!] Searching for Emails : ")
    emailhunter(*url)
    color.Cyan("\n[!] Identified  Subdomains : ")
    opendata(*url)
    color.Cyan("\n[!] Making connection with virustotal : ")
    virustotal(*url)
    color.Cyan("\n [!] Making connection with Threatcrowd : ")
    threatcrowd(*url)
    }
}}else {
    color.Red("Error : Missing Paramater '--url'")
    color.Green("Usage : go run gorecon.go --url example.com")
}
} 
//Function 1 
//Following code is for performing domain lookup
// I could have used hackertarget's API for domainlookup() but instead I used net package for this , 
//In future I will remove all the instances where I am using hackertarget's api (in version 2.0)
func domainlookup(name string ) { //Defining domain lookup function 
	color.Red("\nCanonical Name (CNAME) ")
	color.Red("+-----------------------------------------+")
	cname, _ := net.LookupCNAME(name)
	fmt.Println("[+]",cname) //printing cname
	color.Red("\nTXT records ")
	color.Red("+-----------------------------------------+")
	txtrecords, _ := net.LookupTXT(name) 
 
	for _, txt := range txtrecords {
		fmt.Println("[+]",txt)//printing txt records 
	}
	color.Red("\nA and AAAA  ")
	color.Red("+-----------------------------------------+")
	iprecords, _ := net.LookupIP(name)
	for _, ip := range iprecords {
		fmt.Println("[+]",ip)//printing AAAA / A records 
	}
	color.Red("\nName Server(s) (NS)  ")
	color.Red("+-----------------------------------------+")
	nameserver, _ := net.LookupNS(name)
	for _, ns := range nameserver {
		fmt.Println("[+]",ns)  //Printing nameservers 
	}
	color.Red("\nMX ")
	color.Red("+-----------------------------------------+")
	mxrecords, _ := net.LookupMX(name)
	for _, mx := range mxrecords {
		fmt.Println("[+]",mx.Host, mx.Pref) // Printing MX records 
	}
}

//function 2 

func whoislookup(name string ) { // defining whoislookup function 
	result, err := whois.Whois(name)

		if err != nil {
				fmt.Println(err)
		}

		fmt.Println(result) // printing whois 
}

//function 3 

func shownmap(name string ){ //defining shownmap function 
	url := "https://api.hackertarget.com/nmap/?q=" + name
	color.Green("NMAP scan for : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the nmap as a string %s
	fmt.Printf("%s\n", html)
}
func showzone(name string ){
	url := "https://api.hackertarget.com/zonetransfer/?q=" + name
	color.Green("Zone Transfer Result for : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the zone transfer result as a string %s
	fmt.Printf("%s\n", html)

}
func shareddns(name string ){
	url := "https://api.hackertarget.com/findshareddns/?q=" + name
	color.Green("Shared DNS servers Result for : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the shared dns  result as a string %s
	fmt.Printf("%s\n", html)
}
func extractlinks(url string) {
	url = "http://" + url
	c := colly.NewCollector(
		colly.AllowedDomains(),
	)

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		// Print link
		color.Green("Link found : %q -> %s\n", e.Text, link)
	})

	// Before making a request print "Visiting ..."
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})
       
	c.Visit(url)
}
func reversedns(name string ){
	url := "https://api.hackertarget.com/reversedns/?q=" + name
	color.Green("Reverse DNS lookup for  : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the revers dns  result as a string %s
	fmt.Printf("%s\n", html)
}
func subnet(name string ){
	url := "https://api.hackertarget.com/subnetcalc/?q=" + name
	color.Green("Calculated subnet for  : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the subnet result as a string %s
	fmt.Printf("%s\n", html)
}
//the below function currently returns , either 200 or 404 response , will modify this in future
func adminpanel(uk string) {  //defining admin panel bruteforce function 
	url:=uk
    url = "http://" + uk   //appending https:// schema
	
	color.Cyan("Note : Screenshots will be saved in the same directory  ")
	
	color.Red("Admin Panel BruteForce")
    file, err := os.Open("read.txt") // opening file containing paths 
    if err != nil {
        log.Fatal(err)
    }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var i string
    for scanner.Scan() {
		scanner.Text()
		i = scanner.Text()
		var name string
        name =url + scanner.Text() 
		resp, err := http.Get(name) 
		if err != nil {
			log.Fatal(err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
			color.Green(name) // logging 200 - 399 responses 
			var k string
			k = i
			r := strings.NewReplacer(`/`, "-", `/`, "-",".","-")
			     color.Yellow("\n [!] Taking screenshot : ")
			     color.Cyan(" [!] Saving Screenshot as ==> : " + uk + r.Replace(k) + ".png" )

			 ////////////////////////////////////////////////////////////////////////////
             
	            var test1 string
	            test1 = "http://webshot.okfnlabs.org/api/generate?url=" + name 
	             color.Blue(" [!] Screen shot status  : ",)
        	     resp, err := http.Get(test1)
	        // handle the error if there is one
	             if err != nil {
		          panic(err)
         	    }
	        // do this now so it won't be forgotten
	         defer resp.Body.Close()
	        // reads html as a slice of bytes
	        html, err := ioutil.ReadAll(resp.Body)
	        if err != nil {
		    panic(err)
	         }
	
	         // show the nmap as a string %s
             //	fmt.Printf("%s\n", html)
	         var s string
	        s = string(html)
	        if s == "Unable to take a screenshot"{
		    color.Red(" [!] Error , Unable to take a screenshot\n")
	        } else {
		    response, err := http.Get(test1) 
		     if err != nil {
			 log.Fatal(err)
	    	 }
		    defer response.Body.Close()
	
		     // Create output file
		     outFile, err := os.Create(uk + r.Replace(k) +  ".png")
		     if err != nil {
		    	log.Fatal(err)
	        	}
        	defer outFile.Close()
	
		// Copy data from HTTP response to file
		     _, err = io.Copy(outFile, response.Body)
		     if err != nil {
		    	log.Fatal(err)
	        	}
            	color.Green(" [!] Screenshot Saved successfully\n")	
	       }
				
        
} else {
			color.Red(name) // logging responses other than 200 - 399
		
		}
		// Print the HTTP Status Code and Status Name
		fmt.Println( resp.StatusCode, http.StatusText(resp.StatusCode))
	}
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
func dirbrute(uk string) {  //directory  bruteforce function 
	url:=uk
	url = "http://" + uk + "/"   //appending https:// schema
	color.Cyan("Note : Screenshots will be saved in the same directory  ")
	color.Red("Directory BruteForce")
    file, err := os.Open("paths.txt") // opening file containing paths 
    if err != nil {
        log.Fatal(err)
    }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var i string
    for scanner.Scan() {
		scanner.Text()
		i = scanner.Text()
		var name string
        name =url + scanner.Text() 
		resp, err := http.Get(name) 
		if err != nil {
			log.Fatal(err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
			color.Green(name) // logging 200 - 399 responses 
			var k string
			k = i
			r := strings.NewReplacer(`/`, "-", `/`, "-",".","-")
			     color.Yellow("\n [!] Taking screenshot : ")
			     color.Cyan(" [!] Saving Screenshot as ==> : " + uk + r.Replace(k) + ".png" )

			 ////////////////////////////////////////////////////////////////////////////
             
	            var test1 string
	            test1 = "http://webshot.okfnlabs.org/api/generate?url=" + name 
	             color.Blue(" [!] Screen shot status  : ",)
        	     resp, err := http.Get(test1)
	        // handle the error if there is one
	             if err != nil {
		          panic(err)
         	    }
	        // do this now so it won't be forgotten
	         defer resp.Body.Close()
	        // reads html as a slice of bytes
	        html, err := ioutil.ReadAll(resp.Body)
	        if err != nil {
		    panic(err)
	         }
	
	      
	         var s string
	        s = string(html)
	        if s == "Unable to take a screenshot" {
            color.Red("[!] Error , Unable to take a screenshot\n")
	        } else {
		    response, err := http.Get(test1) 
		     if err != nil {
			 log.Fatal(err)
	    	 }
		    defer response.Body.Close()
	
		     // Create output file
		     outFile, err := os.Create(uk + r.Replace(k) +  ".png")
		     if err != nil {
		    	log.Fatal(err)
	        	}
        	defer outFile.Close()
	
		// Copy data from HTTP response to file
		     _, err = io.Copy(outFile, response.Body)
		     if err != nil {
		    	log.Fatal(err)
	        	}
            	color.Green(" [!] Screenshot Saved successfully\n")	
	       }
				
        
} else {
			color.Red(name) // logging responses other than 200 - 399
		
		}
		// Print the HTTP Status Code and Status Name
		fmt.Println( resp.StatusCode, http.StatusText(resp.StatusCode))
	}
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
func conffile(url string){ // Function for bruteforcing configuration Files 
	url = "http://" + url + "/" //appending https:// schema
	color.Red("Configuration File Bruteforce started : . . . . .  ")
    file, err := os.Open("conf.txt") // opening file containing paths 
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
		scanner.Text()
		var name string
        name =url + scanner.Text() 
		resp, err := http.Get(name) 
		if err != nil {
			log.Fatal(err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
			color.Green(name) // logging 200 - 399 responses 
			color.Green("Success -- > File found ")
		} else {
			color.Red(name) // logging responses other than 200 - 399
		}
    }


    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
func getheader(url string){
		url = "http://" + url 
		color.Cyan("[+] Sending Request .....\n ")
		resp, err := http.Get(url)
		if err != nil {
				panic(err)
		}
		defer resp.Body.Close()
  
		for k, v := range resp.Header {
				fmt.Print(k)
				fmt.Print(" : ")
				fmt.Println(v)
		}
  }
  func geoip(url string ){
	var url1 string
	url1 = "https://api.hackertarget.com/geoip/?q=" + url
	color.Green("GeoIp Lookup for domain : %s" , url)
	resp, err := http.Get(url1)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the GeoIPresult as a string %s
	color.Cyan("%s\n", html)	  
  }
  func getcms(url1 string){
    //Note : This API may expire soon , so better use your own whatcms API
    var app string
    color.Red("Enter WHATCMS's API , or press enter to use existing API key")
    fmt.Scanf("%s",&app)
    fmt.Scanf("%s",&app)
    if(app == ""){
    api1 := "1559aa8079494cab03d0a9a1a555c5c01ace8e2b90a4ac823cb792be2d1235315714b7"
	url := "https://whatcms.org/APIEndpoint?key="+api1+"&url=http://" + url1
	color.Yellow("\n[+] Checking CMS")
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	//var s string
	b := []byte(html)
	fmt.Printf("\n") 
	if(strings.Contains(string(html), "200")){
		//The Trimming below is Horrible, It is dirty , but it did Work
		color.Green("[!] Success CMS Found \n\n")
		r := strings.NewReplacer(`{"request":"https:\/\/whatcms.org\/APIEndpoint?key=1559aa8079494cab03d0a9a1a555c5c01ace8e2b90a4ac823cb792be2d1235315714b7&url=http:\/\/` + url1 + `","request_web":"https:\/\/whatcms.org\/?s=http%3A%2F%2F` + url1, "", `","result":{"code":200,"msg":"Success",`, "",`"}}`,"",`\`,"",`,`,"\n")
    color.Cyan(r.Replace(string(b)))
	}else{
		color.Red("\n[+] Sorry Something Went Wrong - Unable to find CMS")
    }}else {
        api1 := app
        url := "https://whatcms.org/APIEndpoint?key="+api1+"&url=http://" + url1
	color.Yellow("\n[+] Checking CMS")
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	//var s string
	b := []byte(html)
	fmt.Printf("\n") 
	if(strings.Contains(string(html), "200")){
		//The Trimming below is Horrible, It is dirty , but it did Work
		color.Green("[!] Success CMS Found \n\n")
		r := strings.NewReplacer(`{"request":"https:\/\/whatcms.org\/APIEndpoint?key=`+api1+`&url=http:\/\/` + url1 + `","request_web":"https:\/\/whatcms.org\/?s=http%3A%2F%2F` + url1, "", `","result":{"code":200,"msg":"Success",`, "",`"}}`,"",`\`,"",`,`,"\n")
    color.Cyan(r.Replace(string(b)))
	}else{
		color.Red("\n[+] Sorry Something Went Wrong - Unable to find CMS")
    }
    }


  }
  func emailhunter(url1 string){
    //Repace api1 with your api key 
    var api1 string 
    color.Red("This require hunter.io'Api Key ")
    color.Cyan("Enter API key or Press enter to skip email check ")
    fmt.Scanf("%s",&api1)
    fmt.Scanf("%s",&api1)
    if(api1  == ""){
        color.Red("No key provided ")
    }else { 
	url := "https://api.hunter.io/v2/domain-search?domain="+url1+"&api_key="+api1
	color.Yellow("\n[+] Checking Emails ")
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	//var s string
	b := []byte(html)
	fmt.Printf("\n") 
	if(strings.Contains(string(html), "200")){
		//This trimming literally took me 15 minutes , xD
		color.Green("[!] Success Email(s) Found \n\n")
		r := strings.NewReplacer(`todo `, "", `todo`, "",`todo`,"",`todo`,"",`todo`,"\n")
    color.Cyan(r.Replace(string(b)))
	}else{
		color.Red("\n[+] Unable to find Emails ")
    }
}
}
func opendata(name string){
	url := "http://dns.bufferover.run/dns?q=." + name
	color.Green("Data found in Rapid7 Open Data's Project Sonar : %s", name)
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()
	// reads html as a slice of bytes
	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	// show the zone transfer result as a string %s
	color.Green("%s\n", html)
  }

    func virustotal(url1 string){
        var err error
        color.Green("Opening Browser window")
		time.Sleep(1000* time.Millisecond)
        time.Sleep(1000* time.Millisecond)
        var api1 string
        app := "https://pastebin.com/raw/46zp00y0" 
	   resp, err := http.Get(app)
	// handle the error if there is one
	   if err != nil {
		 panic(err)
	   }
	   // do this now so it won't be forgotten
	   defer resp.Body.Close()
	  // reads html as a slice of bytes
	 html, err := ioutil.ReadAll(resp.Body)
	 if err != nil {
		panic(err)
     }
     app = string(html)
     api1 = app
        url := "https://www.virustotal.com/vtapi/v2/domain/report?apikey="+api1+"&domain="+url1
    
        switch runtime.GOOS {
        case "linux":
            err = exec.Command("xdg-open", url).Start()
        case "windows":
            err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
        case "darwin":
            err = exec.Command("open", url).Start()
        default:
            err = fmt.Errorf("unsupported platform")
        }
        if err != nil {
            log.Fatal(err)
        
      }
    }
func threatcrowd(url string) {
        var err error
        color.Green("Opening Browser window")
		time.Sleep(1000* time.Millisecond)
        time.Sleep(1000* time.Millisecond)
        url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+url
        switch runtime.GOOS {
        case "linux":
            err = exec.Command("xdg-open", url).Start()
        case "windows":
            err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
        case "darwin":
            err = exec.Command("open", url).Start()
        default:
            err = fmt.Errorf("unsupported platform")
        }
        if err != nil {
            log.Fatal(err)
        }
    
    }
