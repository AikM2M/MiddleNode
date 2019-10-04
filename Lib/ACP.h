#pragma once

#include <iostream>
#include <string>
#include <list> // http://www.cplusplus.com/reference/list/list/

//extern class resource Resource2ACPTable;
using namespace std;

class AttributeValuePair    // its ACRi i.e. a single Attribute-Value pair of ACR
{
public:
    AttributeValuePair();
    ~AttributeValuePair();
    string attribute;
    string value;
    // didnt make getter function as they may waste memory by returning the object.
    bool setAttributeValuePair(string, string);
    bool setAttributeValuePair(string, int);
};

class ACR   // its "acr(k)" i.e. k'th rule; It is one single rule, containing multiple 
//attributes (accessControlOrigiator, accessControlOperation, accessControlContext)
{
public:
    ACR();
    ~ACR();
    void addACRi(AttributeValuePair);
    list<AttributeValuePair> ACRiList;
};

class ACP // A single ACP contains // One set of multiple rules. at least one 
//self-priviliges and one priviliges rule 
{
public:
    ACP();
    ~ACP();
    void addACR(ACR);
    list<ACR> ACRList;
};

class Resource2ACPTable // first column is only one resource (CSE/AE -ID),
// second contains multiple ACP objects
{
public:
    Resource2ACPTable();
    ~Resource2ACPTable();
    string resourceID;
    list<ACP*> ACPList; // a list of pointers to multiple ACP objects
    void addACP(ACP&);
};

//
//  func
//

void printACP(ACP ACPObj);

void generateACP();

string intToString(int x);

bool checkRequestACP(ACR& requestObj);
// ACR class contains attribute-value pairs which are just like the request message
// This would be a generic/scalable function

bool checkRequestACP(string to, string From, unsigned short op, unsigned short ty);

extern Resource2ACPTable resource2ACPTableObj;
