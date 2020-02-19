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
	string ip = "192.168.0.1";

	// regex ip_basic_format_regex ("(^(\d{1,3}\.){3}\d{1,3}$)");
	// regex ip_zero_validation_regex ("((^0\d+)|(\.0\d+))");

	smatch matches;
	regex reg("^(\\d{1,3}\\.){3}\\d{1,3}$");

	regex_match(ip, matches, reg);

	cout<<matches.size()<<endl;
	cout<<matches.str()<<endl<<endl;
	cout<<matches[0]<<endl;
	cout<<matches[1]<<endl;
}
