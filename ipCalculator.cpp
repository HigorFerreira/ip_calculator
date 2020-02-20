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

	// regex ip_basic_format_regex ("(^(\d{1,3}\.){3}\d{1,3}$)");
	// regex ip_zero_validation_regex ("((^0\d+)|(\.0\d+))");

	smatch matches;
	regex reg("(^0\\d+)|(\\.0\\d+)");

	regex_search(ip, matches, reg);

	sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
	sregex_iterator lastMatch;

	while(currentMatch != lastMatch){
		smatch match = *currentMatch;
		cout<<match.str()<<endl;
		currentMatch++;
	}
}
