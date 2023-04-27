#include <iostream>
#include "SecLib.h"

int main() {
	static SecLib::FileID fileID;
	
	std::cout << "IconCheck:\n";
	std::vector<std::string> iconRes = fileID.iconCheck();
	if (iconRes.size() != 0) {
		for (int i = 0; i < iconRes.size(); i++) {
			std::cout << "[IconCheck] Found --> " << iconRes[i] << std::endl;
		}
	}

	std::cout << std::endl;

	std::cout << "HostCheck:\n";
	std::vector<std::string> hostRes = fileID.hostCheck();
	if (hostRes.size() != 0) {
		for (int i = 0; i < hostRes.size(); i++) {
			std::cout << "[HostCheck] Found --> " << hostRes[i] << std::endl;
		}
	}

	std::cout << std::endl;

	std::cout << "DriverCheck:\n";
	std::vector<std::string> driverRes = fileID.driverCheck();
	if (driverRes.size() != 0) {
		for (int i = 0; i < driverRes.size(); i++) {
			std::cout << "[DriverCheck] Found --> " << driverRes[i] << std::endl;
		}
	}

	std::cout << std::endl;

	//Slow
	std::cout << "StringCheck:\n";
	std::vector<std::string> stringRes = fileID.stringCheck();
	if (stringRes.size() != 0) {
		for (int i = 0; i < stringRes.size(); i++) {
			std::cout << "[StringCheck] Found --> " << stringRes[i] << std::endl;
		}
	}

	std::cout << std::endl;

	//Slow
	std::cout << "SigCheck:\n";
	std::vector<std::string> sigRes = fileID.sigCheck();
	if (sigRes.size() != 0) {
		for (int i = 0; i < sigRes.size(); i++) {
			std::cout << "[SigCheck] Found --> " << sigRes[i] << std::endl;
		}
	}

	std::cout << std::endl;
	
	std::cout << "Finished!" << std::endl;
}