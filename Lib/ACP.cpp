
#include "ACP.h"

#define noOfACR 4

using namespace std;

Resource2ACPTable resource2ACPTableObj;

//
//  func
//

void printACP(ACP ACPObj)
{
    cout << "printACP" << endl;
    list<ACR>::iterator ACRIt; // traverse list of rules in a single ACP
    list<AttributeValuePair>::iterator attributeValuePairIt; // traverse attributes in a single rule
    unsigned int ACRCounter;
    unsigned int attributeValuePairCounter;
    for (ACRCounter = 0, ACRIt = ACPObj.ACRList.begin(); ACRIt != ACPObj.ACRList.end(); ACRCounter++, ACRIt++)
    {
        cout << "ACR " << ACRCounter << endl;
        for (attributeValuePairCounter = 0, attributeValuePairIt = ACRIt->ACRiList.begin(); attributeValuePairIt != ACRIt->ACRiList.end(); attributeValuePairCounter++, attributeValuePairIt++)
        {
            cout << "Counter " << attributeValuePairCounter;
            cout << " : attribute : " << attributeValuePairIt->attribute;
            cout << "\t, value : " << attributeValuePairIt->value;
            cout << endl;
        }
    }
}

void generateACP()
{
    AttributeValuePair * attributeValuePairObj;
    ACR * ACRObj;
    ACP* ACPObjPtr;
    // first ACR in first ACP
    attributeValuePairObj = new AttributeValuePair;
    ACRObj = new ACR;
    attributeValuePairObj->setAttributeValuePair("to", "1.1.1");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("From", "2.2.1");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("op", "1");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("ty", "2");
    ACRObj->addACRi(*attributeValuePairObj);
    
    ACPObjPtr = new ACP;
    ACPObjPtr->addACR(*ACRObj);
    // dont add acp yet
//    resource2ACPTableObj.addACP(*ACPObjPtr); // a new pointer to the ACP object pointed by ACPObjPtr is added in resourceObj.
                                    //  printACP(*(resourceObj.ACPList.front()));
                                    // now two pointers are pointing to a single object. So, ACPObjPtr can point to new ACP object
    // second ACR in first ACP
    attributeValuePairObj = new AttributeValuePair;
    ACRObj = new ACR;
    attributeValuePairObj->setAttributeValuePair("to", "1.1.12");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("From", "2.2.12");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("op", "11");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("ty", "22");
    ACRObj->addACRi(*attributeValuePairObj);
    
//    ACPObjPtr = new ACP;  // add to ACP already created ago
    ACPObjPtr->addACR(*ACRObj);
    resource2ACPTableObj.addACP(*ACPObjPtr);
    
    // first ACR in second ACP
    attributeValuePairObj = new AttributeValuePair;
    ACRObj = new ACR;
    attributeValuePairObj->setAttributeValuePair("to", "1.1.22");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("From", "2.2.22");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("op", "21");
    ACRObj->addACRi(*attributeValuePairObj);
    attributeValuePairObj->setAttributeValuePair("ty", "32");
    ACRObj->addACRi(*attributeValuePairObj);
    
    ACPObjPtr = new ACP;
    ACPObjPtr->addACR(*ACRObj);
    resource2ACPTableObj.addACP(*ACPObjPtr);

                                    
// delete ptrs
    attributeValuePairObj = 0;
    delete attributeValuePairObj;
    ACRObj = 0;
    delete ACRObj;
    ACPObjPtr = 0;
    delete ACPObjPtr;
    cout << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" << endl;
}

string intToString(int x)
{
    string str;
    if (x < 10)
    {
        str = char(x) + '0';
        return str;
    }
    str = char(x % 10) + '0';
    return intToString(x / 10) + str;
}

bool checkRequestACP(ACR & requestObj)
// ACR class contains attribute-value pairs which are just like the request message
// This would be a generic/scalable function
{
    //  cout << requestObj.ACRiList.back().attribute << endl;
    list<ACP*>::iterator ACPIt; // A single ACP pointer List having a list of ACP pointed by it
    list<ACR>::iterator ACRIt; // traverse list of rules in a single ACP
    list<AttributeValuePair>::iterator attributeValuePairIt; // traverse attributes in a single rule
    list<AttributeValuePair>::iterator requestAttributeValuePairIt; // traverse attributes in a single rule
    unsigned int ACPCounter;
    unsigned int ACRCounter;
    unsigned int attributeValuePairCounter;
    bool checkerFlag = 0;
// traverse the list of ACP
    for (ACPCounter = 0, ACPIt = resource2ACPTableObj.ACPList.begin(); 
        ACPIt != resource2ACPTableObj.ACPList.end(); ACPCounter++, ACPIt++)
    {
// traverse the list of ACR within the single ACP
        for (ACRCounter = 0, ACRIt = (*ACPIt)->ACRList.begin();
            ACRIt != (*ACPIt)->ACRList.end(); ACRCounter++, ACRIt++)
        {
            checkerFlag = 1;
            //      cout << "ACR " << ACRCounter << endl;
            for (attributeValuePairCounter = 0, attributeValuePairIt = ACRIt->ACRiList.begin(),
                requestAttributeValuePairIt = requestObj.ACRiList.begin();
                attributeValuePairIt != ACRIt->ACRiList.end();
                attributeValuePairCounter++, attributeValuePairIt++, requestAttributeValuePairIt++)
            {
                // yet this loop assumes that only four values are to be iterated which are in a strict pattern according to request.
                if (requestAttributeValuePairIt == requestObj.ACRiList.end() || /* request does't have enough parameter to match the ACR */
                    attributeValuePairIt->attribute != requestAttributeValuePairIt->attribute || /* Attributes doesn't match (assumption of fixed values fail) */
                    attributeValuePairIt->value != requestAttributeValuePairIt->value) /* values of attributes doesn't match    */
                {
                    checkerFlag = 0;
                    /*                  cout << attributeValuePairIt->attribute << "\treq " << requestAttributeValuePairIt->attribute << "\tval " <<
                                            attributeValuePairIt->value << "\treq " << requestAttributeValuePairIt->value << endl;
                        */
                }
            }
            if (checkerFlag == 1) // whole ACR has been successfully matched.!
            {
                //              cout << "matched.!" << endl;
                return 1;
            }
        }
    }
    return 0;
}

//  /*

bool checkRequestACP(string to, string From, unsigned short op, unsigned short ty)
{
    ACR ACRObj; // will auto-delete after this function ends
    AttributeValuePair* attributeValuePairObj;
    attributeValuePairObj = new AttributeValuePair;
    attributeValuePairObj->setAttributeValuePair("to", to);
    ACRObj.addACRi(*attributeValuePairObj);
    attributeValuePairObj = new AttributeValuePair;
    attributeValuePairObj->setAttributeValuePair("From", From);
    ACRObj.addACRi(*attributeValuePairObj);
    attributeValuePairObj = new AttributeValuePair;
    attributeValuePairObj->setAttributeValuePair("op", intToString(op));
    ACRObj.addACRi(*attributeValuePairObj);
    attributeValuePairObj = new AttributeValuePair;
    attributeValuePairObj->setAttributeValuePair("ty", intToString(ty));
    ACRObj.addACRi(*attributeValuePairObj);
    //  cout << ACRObj.ACRiList.back().attribute << endl;
        //---------
    attributeValuePairObj = 0;
    /*
        should I delete attributeValuePairObj pointer ???
        delete attributeValuePairObj;
        attributeValuePairObj = new AttributeValuePair;
        attributeValuePairObj->setAttributeValuePair("ty", intToString(ty));
    //  */
    if (checkRequestACP(ACRObj))
        return 1;
    return 0;
}

//  */

//
//  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//
//                          Functions
//
//  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//


//
//  AttributeValuePair   -=-=-=-=-=-=-=-=-
//

AttributeValuePair::AttributeValuePair()
{
    //  cout << "ACRk Object created." << endl;
}

AttributeValuePair::~AttributeValuePair()
{
    //  cout << "AttributeValuePair Object deleted." << endl;
}

bool AttributeValuePair::setAttributeValuePair(string attri, string val)
{
    attribute = attri;
    value = val;
    return 1;
}

bool AttributeValuePair::setAttributeValuePair(string attri, int val)
{
    string strVal = intToString(val);
    setAttributeValuePair(attri, strVal);
    return 1;
}

//
//  ACR -=-=-=-=-=-=-=-=-
//

ACR::ACR()
{
    //  cout << "ACR Object created." << endl;
}

ACR::~ACR()
{
    //  cout << "ACR Object deleted." << endl;
}

void ACR::addACRi(AttributeValuePair attributeValuePairObj)
{
    ACRiList.push_back(attributeValuePairObj);
}

//
//  ACP -=-=-=-=-=-=-=-=-
//

ACP::ACP()
{
    //  cout << "ACP Object created." << endl;
}

ACP::~ACP()
{
    cout << "ACP Object deleted." << endl;
}

void ACP::addACR(ACR ACRObj)
{
    ACRList.push_back(ACRObj);
}

//
//  resource    -=-=-=-=-=-=-=-=-
//

Resource2ACPTable::Resource2ACPTable()
{
    //  cout << "resource Object created." << endl;
}

Resource2ACPTable::~Resource2ACPTable()
{
    //  cout << "resource Object deleted." << endl;
}

void Resource2ACPTable::addACP(ACP & ACPObj1)
{
    ACP** ACPObjDPtr = new ACP*;
    *ACPObjDPtr = &ACPObj1;
    ACPList.push_back(*ACPObjDPtr);
    ACPObjDPtr = 0;
}
