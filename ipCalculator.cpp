#include<iostream>
#include<regex>
#include<vector>
#include<functional>

using namespace std;

class IP {
	public:
		vector<int> octets;
		vector<int> mask = { 0, 0, 0, 0 };
		vector<string> errors;
		char ipClass;
		
		string completeIpAddress;
		int cdir;

		//============================ VALIDADORES =================================================

		/**
		 * Função de validação do IP pelo formato
		 * Retorna verdadeiro para um ip no formato XXX.XXX.XXX.XXX,
		 * X um dígito decimal, podendo o número de digitos variar
		 * de 1 à 3.
		 * Retorna falso caso contrário  * */
		bool ipFormatValidator(string &ip){
			smatch ipFormatMatch;
			regex ipFormatRegex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
			if(regex_match(ip, ipFormatMatch, ipFormatRegex)){
				return true;
			}
			else{
				errors.push_back("O ip digitado possui um formato incorreto");
				return false;
			}
		}

		/**
		 * Função que verifica a existência de digitos zero
		 * inválidos no ip, exemplo: 192.01.0.1
		 * **/
		bool ipZerosValidator(string &ip){
			bool valid = true;
			smatch matches;
			regex reg("(^0\\d+)|(\\.0\\d+)");

			regex_search(ip, matches, reg);

			sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
			sregex_iterator lastMatch;

			while(currentMatch != lastMatch){
				valid = false;
				smatch match = *currentMatch;
				errors.push_back("O bloco: " + match.str() + "está incorreto");
				currentMatch++;
			}

			return valid;
		}

		/**
		 * Validação do intervalo dos octetos
		 * **/
		bool octetsRageValidator(){
			bool valid = true;

			for(size_t i = 0; i < octets.size(); i++){
				if(octets.at(i) < 0 || octets.at(i) > 255){
					valid = false;
					errors.push_back("O " + to_string(i+1) + "º octeto \"" + to_string(octets.at(i)) + "\" está fora de intervalo.");
				}
			}

			return valid;
		}

		//============================ VALIDADORES =================================================

		/**
		 * Função que separa os octetos
		 * **/
		bool breakOctets(string &ip){
			smatch matches;
			regex reg("\\d{1,3}");

			regex_search(ip, matches, reg);

			sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
			sregex_iterator lastMatch;

			while(currentMatch != lastMatch){
				smatch match = *currentMatch;
				octets.push_back(stoi(match.str()));
				currentMatch++;
			}

			return true;
		}

		/**
		 * Função que define o classe do Ip,
		 * e suas máscaras na notação decimal e CDIR
		 * **/
		bool setIpClass(){
			if(octets.size() < 1) return false;

			if(octets.at(0) >> 7 == 0){
				ipClass = 'A';
				mask[0] = 0xff;
				cdir = 8;
			}
			else if(octets.at(0) >> 6 == 0b10){
				ipClass = 'B';
				mask[0] = 0xff; mask[1] = 0xff;
				cdir = 16;
			}
			else if(octets.at(0) >> 5 == 0b110){
				ipClass = 'C';
				mask[1] = 0xff; mask[0] = 0xff; mask[2] = 0xff;
				cdir = 24;
			}
			else if(octets.at(0) >> 4 == 0b1110){
				ipClass = 'D';
				mask[0] = 0xff; mask[1] = 0xff; mask[2] = 0xff; mask[3] = 0xff;
				cdir = 32;
			}
			else if(octets.at(0) >> 4 == 0b1111){
				ipClass = 'E';
				mask[0] = 0xff; mask[1] = 0xff; mask[2] = 0xff; mask[3] = 0xff;
				cdir = 32;
			}
			else{
				return false;
			}

			return true;
		}

	public:

		/**
		 * Construtor para IP com classe **/
		IP(string ip){
			this->octets = { 192, 18, 0, 1 };
			this->mask = { 255, 255, 255, 0 };
			this->cdir = 24;
			this->ipClass = 'C';
			this->completeIpAddress = "192.18.0.1";
		}

		/**
		 * Construtor para IP sem classe **/
		IP(string ip, string mask){

		}

		void test(){
			if(errors.size() == 0){
				cout<<octets.at(0);
			}
			else{
				cout<<errors.at(0);
			}
		}

		void print(void (*callback)(IP*) = NULL){
			if(callback) callback(this);
			else cout<<"No function passed"<<endl;
		}
};

int main(){
	
	IP ip("192.18.0.1");

	ip.print();
}