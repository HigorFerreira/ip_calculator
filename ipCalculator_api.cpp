#include <iostream>
#include <clocale>
#include <cmath>
#include <bitset>
#include <regex>
#include <vector>
#include <functional>

using namespace std;

class IP
{
public:
	const short MASK_CDIR = 0;
	const short MASK_DECC = 1;

	vector<int> *octets = 0;
	vector<int> *mask = 0;
	vector<string> *errors = new vector<string>;
	char *ipClass = NULL;

	string *completeIpAddress;
	int *cdir = 0;

	int *numberOfHosts = NULL;

	//============================ VALIDADORES =================================================

	/**
		 * Função de validação do IP pelo formato
		 * Retorna verdadeiro para um ip no formato XXX.XXX.XXX.XXX,
		 * X um dígito decimal, podendo o número de digitos variar
		 * de 1 à  3.
		 * Retorna falso caso contrário  * */
	bool ipFormatValidator(string &ip)
	{
		smatch ipFormatMatch;
		regex ipFormatRegex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
		if (regex_match(ip, ipFormatMatch, ipFormatRegex))
		{
			return true;
		}
		else
		{
			errors->push_back("O ip digitado possui um formato incorreto.");
			return false;
		}
	}

	/**
		 * Função de validação do formato das máscaras **/
	bool maskFormatValidator(string &ip)
	{
		smatch maskFormatMatch;
		regex maskFormatRegex("(^\\/\\d{1,2}$)|(^(\\d{1,3}\\.){3}\\d{1,3}$)");
		if (regex_match(ip, maskFormatMatch, maskFormatRegex))
		{
			return true;
		}
		else
		{
			this->errors->push_back("A máscara digitada possui um formato incorreto");
			return false;
		}
	}

	/**
		 * Função que verifica a existência de digitos zero
		 * inválidos no ip, exemplo: 192.01.0.1
		 * **/
	bool ipZerosValidator(string &ip, bool mask = false)
	{
		bool valid = true;
		smatch matches;
		regex reg("(^0\\d+)|(\\.0\\d+)");

		regex_search(ip, matches, reg);

		sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
		sregex_iterator lastMatch;

		while (currentMatch != lastMatch)
		{
			valid = false;
			smatch match = *currentMatch;
			errors->push_back("A parte: \\\"" + match.str() + "\\\" " + (mask ? "da máscara" : "do ip") + " está incorreta, não pode haver dígito precedido por zero.");
			currentMatch++;
		}

		return valid;
	}

	bool maskZeroValidator(string &mask)
	{
		return ipZerosValidator(mask, true);
	}

	/**
		 * Validação do intervalo dos octetos
		 * **/
	bool octetsRangeValidator()
	{
		if (!this->octets)
			throw string("Octetos de IP não definidos");
		bool valid = true;

		iterator<int>(this->octets, [&](int octet, int i) {
			if (octet < 0 || octet > 255)
			{
				valid = false;
				this->errors->push_back("O " + to_string(i + 1) + "º octeto \\\"" + to_string(octet) + "\\\" está fora de intervalo.");
			}
		});

		return valid;
	}

	/**
		 * Validação do intervalo dos octetos de uma máscara decimal
		 * **/
	bool maskOctetsRangeValidator()
	{
		/** Transformando a máscara em binário **/
		string binaryMask = "";
		iterator<int>(this->mask, [&](int el) {
			binaryMask += bitset<8>(el).to_string();
		});
		/** Validando o intervalo da máscara **/
		smatch match;
		regex reg("^1+0+$");
		if (regex_match(binaryMask, match, reg))
		{
			return true;
		}
		else
		{
			this->errors->push_back("A máscara digitada não é válida");
			return false;
		}
	}

	/** Determinação do tipo da máscara **/
	short getMaskType(string &mask)
	{
		smatch match;
		regex reg("^\\/\\d{1,2}$");
		if (regex_match(mask, match, reg))
			return MASK_CDIR;
		else
			return MASK_DECC;
	}

	//============================ VALIDADORES =================================================

	//============================ ITERADORES ==================================================
	template <typename T>
	void iterator(vector<T> *array, function<void(T)> callback)
	{
		for (size_t i = 0; i < array->size(); i++)
		{
			callback(array->at(i));
		}
	}

	template <typename T>
	void iterator(vector<T> *array, function<void(T, size_t)> callback)
	{
		for (size_t i = 0; i < array->size(); i++)
		{
			callback(array->at(i), i);
		}
	}

	template <typename T>
	void iterator(vector<T> *array, function<void(T, size_t, vector<T> *)> callback)
	{
		for (size_t i = 0; i < array->size(); i++)
		{
			callback(array->at(i), i, array);
		}
	}
	//============================ ITERADORES ==================================================

	/**
		 * Função que separa os octetos
		 * **/
	vector<int> *breakOctets(string &ip)
	{
		smatch matches;
		regex reg("\\d{1,3}");
		vector<int> *octets = new vector<int>;

		regex_search(ip, matches, reg);

		sregex_iterator currentMatch(ip.begin(), ip.end(), reg);
		sregex_iterator lastMatch;

		while (currentMatch != lastMatch)
		{
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
	bool setIpParamsBasedOnClass()
	{
		if (!this->octets)
			throw string("Octetos de IP não definidos");
		if (octets->size() < 1)
			return false;

		//Alocação dos octetos da máscara
		this->mask = new vector<int>(4, 0);

		if (octets->at(0) >> 7 == 0)
		{
			ipClass = new char('A');
			mask->at(0) = 0xff;
			this->cdir = new int(8);
		}
		else if (octets->at(0) >> 6 == 0b10)
		{
			ipClass = new char('B');
			mask->at(0) = 0xff;
			mask->at(1) = 0xff;
			this->cdir = new int(16);
		}
		else if (octets->at(0) >> 5 == 0b110)
		{
			ipClass = new char('C');
			mask->at(1) = 0xff;
			mask->at(0) = 0xff;
			mask->at(2) = 0xff;
			this->cdir = new int(24);
		}
		else if (octets->at(0) >> 4 == 0b1110)
		{
			ipClass = new char('D');
			mask->at(0) = 0xff;
			mask->at(1) = 0xff;
			mask->at(2) = 0xff;
			mask->at(3) = 0xff;
			this->cdir = new int(32);
		}
		else if (octets->at(0) >> 4 == 0b1111)
		{
			ipClass = new char('E');
			mask->at(0) = 0xff;
			mask->at(1) = 0xff;
			mask->at(2) = 0xff;
			mask->at(3) = 0xff;
			this->cdir = new int(32);
		}
		else
		{
			return false;
		}

		//Definindo o número de hosts
		this->numberOfHosts = new int(pow(2, 32 - *this->cdir) - 2);

		return true;
	}

	bool getValidatedIp(string &ip)
	{
		bool valid = ipFormatValidator(ip) && ipZerosValidator(ip);
		this->octets = breakOctets(ip);
		valid = octetsRangeValidator() && setIpParamsBasedOnClass();
		this->completeIpAddress = new string(ip);
		return valid;
	}

	bool setIpParamsBasedOnMask(string &mask)
	{
		if (this->mask)
			delete this->mask;
		if (this->ipClass)
		{
			delete this->ipClass;
			this->ipClass = NULL;
		}
		if (this->cdir)
			delete this->cdir;
		if (this->numberOfHosts)
			delete this->numberOfHosts;
		bool valid = true;
		if (getMaskType(mask) == MASK_DECC)
		{
			//Validação e armazenamento da másscara
			valid = maskFormatValidator(mask) && maskZeroValidator(mask);
			this->mask = breakOctets(mask);
			valid = maskOctetsRangeValidator();

			/**
				 * Contagem de zeros para a definição da notação CDIR,
				 * O número CDIR é obtido com (32 - qttZeros)
				 * */
			int numberOfZeros = 0;
			int bit;
			this->iterator<int>(this->mask, [&](int octet) {
				for (size_t i = 0; i < 8; i++)
				{
					int shiftedOctet = octet >> numberOfZeros;
					bit = shiftedOctet & 1;
					if (bit == 0)
						numberOfZeros++;
				}
			});

			this->cdir = new int(32 - numberOfZeros);
		}
		else
		{
			this->mask = new vector<int>;
			this->cdir = new int(stoi(mask.substr(1, 2)));

			valid = *this->cdir > 0 && *this->cdir < 33;
			if (!valid)
			{
				this->errors->push_back("CDIR fora de intervalo.");
				return false;
			}

			/**
				 * Conversão CDIR em decimal **/
			int octet = 0xff;
			size_t iteration = 1;
			do
			{
				octet >>= 1;
				if (iteration % 8 == 0)
				{
					this->mask->push_back(octet);
					octet = 0xff;
				}
				iteration++;
			} while (iteration != *this->cdir + 1);

			if (this->mask->size() < 4)
				this->mask->push_back(octet);
			while (this->mask->size() < 4)
			{
				this->mask->push_back(0xff);
			}

			iterator<int>(this->mask, [](int value, int i, vector<int> *_mask) {
				value = ~value;
				value &= 0xff;
				_mask->at(i) = value;
			});
		}

		this->numberOfHosts = new int(pow(2, 32 - *this->cdir) - 2);

		return valid;
	}

public:
	/**
		 * Construtor para IP com classe **/
	IP(string ip)
	{
		getValidatedIp(ip);
	}

	/**
		 * Construtor para IP sem classe **/
	IP(string ip, string mask)
	{
		getValidatedIp(ip);
		setIpParamsBasedOnMask(mask);
	}

	~IP()
	{
		delete octets;
		delete mask;
		delete errors;
		delete ipClass;
		delete cdir;
		delete completeIpAddress;
	}

	string getDecimalMask()
	{
		string mask = "";
		for (size_t i = 0; i < 3; i++)
		{
			mask += to_string(this->mask->at(i)) + ".";
		}
		return mask + to_string(this->mask->at(3));
	}

	string getFirstAddress(bool usable = false)
	{
		string addressStr = "";
		vector<int> address;
		iterator<int>(this->octets, [&](int oct, int i) {
			address.push_back(oct & this->mask->at(i));
		});

		if (usable)
			address.at(3) += 1;

		for (size_t i = 0; i < 3; i++)
			addressStr += to_string(address.at(i)) + ".";
		return addressStr + to_string(address.at(3));
	}

	string getFirtsUsableAddress()
	{
		return getFirstAddress(true);
	}

	string getBroadcastAddress(bool usable = false)
	{
		string addressStr = "";
		vector<int> address;
		iterator<int>(this->octets, [&](int oct, int i) {
			int maskComplement = ~(this->mask->at(i));
			maskComplement &= 0xff;
			address.push_back(oct | maskComplement);
		});

		if (usable)
			address.at(3) -= 1;

		for (size_t i = 0; i < 3; i++)
			addressStr += to_string(address.at(i)) + ".";
		return addressStr + to_string(address.at(3));
	}

	string getLastUsableAddress()
	{
		return getBroadcastAddress(true);
	}

	void print(function<void(IP *)> callback = NULL)
	{
		if (this->errors->size() > 0)
		{
			cout<<"{\"error\":{\"message\":\"ERRO NO IP: "<<*this->completeIpAddress<<"\",\""<<
			"numberOfErrors\":"<<this->errors->size()<<",\"errors\":[";
			this->iterator<string>(this->errors, [](string error, int i, vector<string> *arr) {
				cout<<"\""<<error<<"\"";
				if(i != arr->size()-1) cout<<",";
			});
			cout<<"]}}";
		}
		else if (this->ipClass && *this->ipClass == 'D')
		{
			cout<<"{\"ip\":{\"ip_address\":\""<< *this->completeIpAddress <<"\","<<
			"\"ip_class\":\""<< *this->ipClass <<"\","<<
			"\"more\":\"Endereço reservado para multicast\"}}";
		}
		else if (this->ipClass && *this->ipClass == 'E')
		{
			cout<<"{\"ip\":{\"ip_address\":\""<< *this->completeIpAddress <<"\","<<
			"\"ip_class\":\""<< *this->ipClass <<"\","<<
			"\"more\":\"Endereço reservado para uso futuro\"}}";
		}
		else
		{
			callback(this);
		}
	}
};

int main(int argc, char *argv[])
{

	setlocale(LC_ALL, "Portuguese");

	short option = stoi(argv[1]);

	if (option > 0 && option < 4)
	{
		IP *ip;

		switch (option)
		{
		case 1:
			ip = new IP(argv[2]);
			break;
		case 2:
			ip = new IP(argv[2], argv[3]);
			break;
		}

		ip->print([&](IP *_ip) {

			cout<<"{\"ip\":{\"ip_address\":\""<<*_ip->completeIpAddress<<"\",\"ip_class\":\""<< (_ip->ipClass ? string(_ip->ipClass) : "")  <<"\","<<
			"\"ip_decc_mask\":\""<< _ip->getDecimalMask() <<"\",\"ip_cidr_mask\":\""<< *_ip->cdir <<"\",\"number_of_hosts\":"<< *_ip->numberOfHosts <<","<<
			"\"lan_address\":\""<< _ip->getFirstAddress() <<"\",\"broadcast_address\":\""<< _ip->getBroadcastAddress() <<"\",\"first_usable_ip\":\""<< _ip->getFirtsUsableAddress() <<"\","<<
			"\"last_usable_ip\":\""<< _ip->getLastUsableAddress() <<"\"}}";
		});
	}
	else
	{
		cout<<"{\"error\":{\"message\":\"Esta opção não existe.\",\"numberOfErrors\":0,\"errors\":[]}}";
	}
}
