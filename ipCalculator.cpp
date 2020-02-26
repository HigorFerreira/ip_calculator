#include<iostream>
#include<regex>
#include<vector>
#include<functional>

using namespace std;

class IP {
	public:
		vector<int> *octets = 0;
		vector<int> *mask = new vector<int>(4, 0);
		vector<string> *errors = new vector<string>;
		char *ipClass = 0;
		
		string *completeIpAddress;
		int *cdir = 0;

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
				errors->push_back("O ip digitado possui um formato incorreto");
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
				errors->push_back("O bloco: " + match.str() + "está incorreto");
				currentMatch++;
			}

			return valid;
		}

		/**
		 * Validação do intervalo dos octetos
		 * **/
		bool octetsRageValidator(){
			bool valid = true;

			for(size_t i = 0; i < octets->size(); i++){
				if(octets->at(i) < 0 || octets->at(i) > 255){
					valid = false;
					errors->push_back("O " + to_string(i+1) + "º octeto \"" + to_string(octets->at(i)) + "\" está fora de intervalo.");
				}
			}

			return valid;
		}

		//============================ VALIDADORES =================================================

		/**
		 * Função que separa os octetos
		 * **/
		vector<int> *breakOctets(string &ip){
			smatch matches;
			regex reg("\\d{1,3}");
			vector<int> *octets = new vector<int>;

			regex_search(ip, matches, reg);

			sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
			sregex_iterator lastMatch;

			while(currentMatch != lastMatch){
				smatch match = *currentMatch;
				octets->push_back(stoi(match.str()));
				currentMatch++;
			}

			return octets;
		}

		/**
		 * Função que define o classe do Ip,
		 * e suas máscaras na notação decimal e CDIR
		 * **/
		bool setIpClass(){
			if(octets->size() < 1) return false;

			if(octets->at(0) >> 7 == 0){
				ipClass = new char('A');
				mask->at(0) = 0xff;
				this->cdir = new int(8);
			}
			else if(octets->at(0) >> 6 == 0b10){
				ipClass = new char('B');
				mask->at(0) = 0xff; mask->at(1) = 0xff;
				this->cdir = new int(16);
			}
			else if(octets->at(0) >> 5 == 0b110){
				ipClass = new char('C');
				mask->at(1) = 0xff; mask->at(0) = 0xff; mask->at(2) = 0xff;
				this->cdir = new int(24);
			}
			else if(octets->at(0) >> 4 == 0b1110){
				ipClass = new char('D');
				mask->at(0) = 0xff; mask->at(1) = 0xff; mask->at(2) = 0xff; mask->at(3) = 0xff;
				this->cdir = new int(32);
			}
			else if(octets->at(0) >> 4 == 0b1111){
				ipClass = new char('E');
				mask->at(0) = 0xff; mask->at(1) = 0xff; mask->at(2) = 0xff; mask->at(3) = 0xff;
				this->cdir = new int(32);
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
			this->octets = breakOctets(ip);
			//this->mask = { 255, 255, 255, 0 };
			this->cdir = new int(24);
			this->ipClass = new char('C');
			this->completeIpAddress = new string("192.18.0.1");
		}

		/**
		 * Construtor para IP sem classe **/
		IP(string ip, string mask){

		}

		~IP(){
			delete octets;
			delete mask;
			delete errors;
			delete ipClass;
			delete cdir;
			delete completeIpAddress;
		}

		void test(){
			if(errors->size() == 0){
				cout<<octets->at(0);
			}
			else{
				cout<<errors->at(0);
			}
		}

		void print(function<void(IP*)> callback = NULL){
			callback(this);
		}
};

int main(){
	
	IP ip("192.18.0.1");

	string message = "Variable in main scope";

	ip.print([&](IP *_ip){
		cout<<"Insite print funtion"<<endl;
		cout<<_ip->completeIpAddress<<endl;
		cout<<"CDIR: \\"<<*_ip->cdir<<endl;
		cout<<"------------------------------------\n";
		cout<<_ip->octets->at(0)<<endl;
		cout<<_ip->octets->at(1)<<endl;
		cout<<_ip->octets->at(2)<<endl;
		cout<<_ip->octets->at(3)<<endl;
		cout<<"------------------------------------\n";
		cout<<"MASK\n";
		cout<<"------------------------------------\n";
		cout<<_ip->mask->at(0)<<endl;
		cout<<_ip->mask->at(1)<<endl;
		cout<<_ip->mask->at(2)<<endl;
		cout<<_ip->mask->at(3)<<endl;
		cout<<"------------------------------------\n";
		cout<<message<<endl<<endl;
	});
}