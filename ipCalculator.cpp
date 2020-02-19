#include<iostream>
#include<regex>
#include<vector>

using namespace std;

// class IP {
// 	private:
// 		vector<int> octets;
// 		vector<string> errors;
// 		char ipClass;
		
// 		string completeIpAddress;
// 		string classlessIpMask;
// 		string classlessIpCdir;
// 	public:
// };

int main(){
	string ip = "0192.168.00.1";

	smatch ip_format;
	smatch zero_errors;

	regex ip_basic_format_regex ("(^(\d{1,3}\.){3}\d{1,3}$)");
	regex ip_zero_validation_regex ("((^0\d+)|(\.0\d+))");

	regex_match(ip, ip_format, ip_basic_format_regex);
	regex_match(ip, zero_errors, ip_zero_validation_regex);
	

	cout<<ip_format.size()<<endl;
	cout<<zero_errors.size()<<endl;
}