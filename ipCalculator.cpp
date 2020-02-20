#include<iostream>
#include<regex>
#include<vector>

using namespace std;

class IP {
	private:
		vector<int> octets;
		vector<string> errors;
		char ipClass;
		
		string completeIpAddress;
		string classlessIpMask;
		string classlessIpCdir;

		/**
		 * Função de validação do IP pelo formato
		 * Retorna verdadeiro para um ip no formato XXX.XXX.XXX.XXX,
		 * X um dígito decimal, podendo o número de digitos variar
		 * de 1 à 3.
		 * Retorna falso caso contrário  * */
		bool ipFormatVerification(string &ip){
			smatch ipFormatMatch;
			regex ipFormatRegex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
			regex_match(ip, ipFormatMatch, ipFormatRegex);
			return !ipFormatMatch.empty();
		}

	public:

		/**
		 * Construtor da classe, no qual todo novo ip é inserido **/
		IP(string ip){
			if(ipFormatVerification(ip)){
				octets.push_back(stoi(ip));
			}
			else{
				errors.push_back("Ip no formato incorreto");
			}
		}

		void test(){
			if(errors.size() == 0){
				cout<<octets.at(0);
			}
			else{
				cout<<errors.at(0);
			}
		}
};

int main(){
	
	IP ip("192.18.0.1");

	ip.test();
}
