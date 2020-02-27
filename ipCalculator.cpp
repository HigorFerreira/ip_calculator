#include<iostream>
#include<clocale>
#include<regex>
#include<vector>
#include<functional>

using namespace std;

class IP {
	public:

		const short MASK_CDIR = 0;
		const short MASK_DECC = 1;

		vector<int> *octets = 0;
		vector<int> *mask = 0;
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
				errors->push_back("O ip digitado possui um formato incorreto.");
				return false;
			}
		}

		/**
		 * Função de validação do formato das máscaras **/
		bool maskFormatValidator(string &ip){
			smatch maskFormatMatch;
			regex maskFormatRegex("(^\\/\\d{1,2}$)|(^(\\d{1,3}\\.){3}\\d{1,3}$)");
			if(regex_match(ip, maskFormatMatch, maskFormatRegex)){
				return true;
			}
			else{
				this->errors->push_back("A m�scara digitada possui um formato incorreto");
				return false;
			}
		}

		/**
		 * Função que verifica a existência de digitos zero
		 * inválidos no ip, exemplo: 192.01.0.1
		 * **/
		bool ipZerosValidator(string &ip, bool mask = false){
			bool valid = true;
			smatch matches;
			regex reg("(^0\\d+)|(\\.0\\d+)");

			regex_search(ip, matches, reg);

			sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
			sregex_iterator lastMatch;

			while(currentMatch != lastMatch){
				valid = false;
				smatch match = *currentMatch;
				errors->push_back("A parte: \"" + match.str() + "\" " + (mask ? "da m�scara" : "do ip") + " est� incorreta, n�o pode haver d�gito precedido por zero.");
				currentMatch++;
			}

			return valid;
		}

		bool maskZeroValidator(string &mask){
			return ipZerosValidator(mask, true);
		}

		/**
		 * Validação do intervalo dos octetos
		 * **/
		bool octetsRangeValidator(){
			if(!this->octets) throw string("Octetos de IP n�o definidos");
			bool valid = true;

			iterator<int>(this->octets, [&](int octet, int i){
				if(octet < 0 || octet > 255){
					valid = false;
					this->errors->push_back("O " + to_string(i+1) + "� octeto \"" + to_string(octet) + "\" est� fora de intervalo.");
				}
			});

			return valid;
		}

		/**
		 * Validação do intervalo dos octetos de uma máscara decimal
		 * **/
		bool maskOctetsRangeValidator(){
			if(!this->mask) throw string("Octetos de m�scara n�o definidos");
			bool valid = true;

			iterator<int>(this->mask, [&](int maskOctet, int i){
				valid = false;
				this->errors->push_back("O " + to_string(i+1) + "� octeto da m�scara \"" + to_string(maskOctet) + "\" est� fora de intervalo.");
			});

			return valid;
		}

		short getMaskType(string &mask){
			smatch match;
			regex reg("^\\/\\d{1,2}$");
			if(regex_match(mask, match, reg))
				return MASK_CDIR;
			else
				return MASK_DECC;
		}

		//============================ VALIDADORES =================================================


		//============================ ITERADORES ==================================================
		template<typename T>
		void iterator(vector<T> *array, function<void(T)> callback){
			for(size_t i = 0; i < array->size(); i++){
				callback(array->at(i));
			}
		}

		template<typename T>
		void iterator(vector<T> *array, function<void(T, size_t)> callback){
			for(size_t i = 0; i < array->size(); i++){
				callback(array->at(i), i);
			}
		}

		template<typename T>
		void iterator(vector<T> *array, function<void(T, size_t, vector<T>*)> callback){
			for(size_t i = 0; i < array->size(); i++){
				callback(array->at(i), i, array);
			}
		}
		//============================ ITERADORES ==================================================

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
		bool setIpParamsBasedOnClass(){
			if(!this->octets) throw string("Octetos de IP n�o definidos");
			if(octets->size() < 1) return false;

			//Alocação dos octetod da máscara
			this->mask = new vector<int>(4, 0);

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
			//Validação do IP
			ipFormatValidator(ip);
			ipZerosValidator(ip);
			//Definição dos octetos
			this->octets = breakOctets(ip);
			//Validando os intervalos dos octetos
			octetsRangeValidator();
			//Setando os parâmetros baseado na classe
			setIpParamsBasedOnClass();

			this->completeIpAddress = new string(ip);
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
			if(this->errors->size() > 0){
				this->iterator<string>(this->errors, [&](string error){
					cout<<error<<endl;
				});
			}
			else{
				callback(this);
			}
		}
};

int main(){
	
	setlocale(LC_ALL, "Portuguese");
	
	IP ip("192.18.05.1");

	string message = "Variable in main scope";

	ip.print([&](IP *_ip){
		cout<<"Insite print funtion"<<endl;
		cout<<*_ip->completeIpAddress<<endl;
		cout<<"Classe: "<<*_ip->ipClass<<endl;
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
