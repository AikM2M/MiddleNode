#pragma once
#include <string>

int ty, op, cst, rsc;
std::string resourceType, cseType, operation, response;
const char* content;
char* _to;
bool RequestReachability;
bool rr, local;
std::string From, csi, api, poa, to, rqi, aei, rn;
std::string con, cnf;
std::string nu;
std::string sur;
int net, nct;
char t1[30];

char AEID[10]; 
std::string buf;
char* to1[5];
char *str_tok;
int i = 0;

extern struct Resource RES;
extern struct regularResource regRES;
extern struct announceableResource ancRES;
extern struct announcedResource ancdRES;
extern struct subordinateResource subRES;
extern struct announceableSubordinateResource ancsubRES;
extern struct announcedSubordinateResource ancdsubRES;

extern struct CreateAE CAE;
extern struct respAE RAE;
extern struct respCnt RCnt;
extern struct respCin RCin;
extern struct respSub RSub;
extern struct notify Ntfy;

const char* CSE_ID = "cse01";
const char* AE_ID;
bool lcl;
bool _notify;
bool MGOJB, Restart;
bool CreateAE;

void resource_type();
void Operation_Type();
void CSE_Type();

void resource_type()
{
	switch (ty)
	{
	case 1:
		resourceType = "accessControlPolicy";
		content = "m2m:acp";
		break;
	case 2:
		resourceType = "AE";
		content = "m2m:ae";
		printf("Content: %s\r\n", content);
		break;
	case 3:
		resourceType = "container";
		content = "m2m:cnt";
		break;
	case 4:
		resourceType = "contentInstance";
		content = "m2m:cin";
		break;
	case 5:
		resourceType = "CSEBase";
		content = "m2m:cb";
		break;
	case 6:
		resourceType = "delivery";
		content = "m2m:dlv";
		break;
	case 7:
		resourceType = "eventConfig";
		content = "m2m:evcg";
		break;
	case 8:
		resourceType = "execInstance";
		content = "m2m:exin";
		break;
	case 9:
		resourceType = "group";
		content = "m2m:grp";
		break;
	case 10:
		resourceType = "locationPolicy";
		content = "m2m:lcp";
		break;
	case 11:
		resourceType = "m2mServiceSubscriptionProfile";
		content = "m2m:mssp";
		break;
	case 12:
		resourceType = "mgmtCmd";
		content = "m2m:mgc";
		break;
	case 13:
		resourceType = "mgmtObj";
		//content = "m2m:cnt";
		break;
	case 14:
		resourceType = "node";
		content = "m2m:nod";
		break;
	case 15:
		resourceType = "pollingChannel";
		content = "m2m:contenth";
		break;
	case 16:
		resourceType = "remoteCSE";
		content = "m2m:csr";
		break;
	case 17:
		resourceType = "request";
		content = "m2m:req";
		break;
	case 18:
		resourceType = "schedule";
		content = "m2m:sch";
		break;
	case 19:
		resourceType = "serviceSubscribedAppRule";
		content = "m2m:asar";
		break;
	case 20:
		resourceType = "serviceSubscribedNode";
		content = "m2m:svsn";
		break;
	case 21:
		resourceType = "statsCollect";
		content = "m2m:stcl";
		break;
	case 22:
		resourceType = "statsConfig";
		content = "m2m:stcg";
		break;
	case 23:
		resourceType = "subscription";
		content = "m2m:sub";
		break;
	case 10001:
		resourceType = "accessControlPolicyAnnc";
		content = "m2m:acpA";
		break;
	case 10002:
		resourceType = "AEAnnc";
		content = "m2m:aeA";
		break;
	case 10003:
		resourceType = "containerAnnc";
		content = "m2m:cntA";
		break;
	case 10004:
		resourceType = "contentInstanceAnnc";
		content = "m2m:cinA";
		break;
	case 10009:
		resourceType = "groupAnnc";
		content = "m2m:grpA";
		break;
	case 10010:
		resourceType = "locationPolicyAnnc";
		content = "m2m:lcpA";
		break;
	case 10013:
		resourceType = "mgmtObjAnnc";
		//content = "m2m:cnt";
		break;
	case 10014:
		resourceType = "nodeAnnc";
		content = "m2m:nodA";
		break;
	case 10016:
		resourceType = "remoteCSEAnnc";
		content = "m2m:csrA";
		break;
	case 10018:
		resourceType = "scheduleAnnc";
		content = "m2m:schA";
		break;
	}
}
void CSE_Type()
{
	switch (cst)
	{
	case 1:
		cseType = "IN_CSE";
		break;
	case 2:
		cseType = "MN_CSE";
		break;
	case 3:
		cseType = "ASN_CSE";
		break;
	}
}
void Operation_Type() //CRUD+N
{
	switch (op)
	{
	case 1:
		operation = "Create";
		break;
	case 2:
		operation = "Retrieve";
		break;
	case 3:
		operation = "Update";
		break;
	case 4:
		operation = "Delete";
		break;
	case 5:
		operation = "Notify";
		break;
	}
}
void Response_Type()
{
	switch (rsc)
	{
		//Informational response class
	case 1000:
		response = "ACCEPTED";
		break;
	case 1001:
		response = "ACCEPTED for nonBlockingRequestSynch";
		break;
	case 1002:
		response = "ACCEPTED for nonBlockingRequestAsynch";
		break;
		//specifies the RSCs for successful responses.
	case 2000:
		response = "OK";
		break;
	case 2001:
		response = "CREATED";
		break;
	case 2002:
		response = "DELETED";
		break;
	case 2004:
		response = "UPDATED";
		break;
		//RSCs for Originator error response class
	case 4000:
		response = "BAD_REQUEST";
		break;
	case 4001:
		response = "RELEASE_VERSION_NOT_SUPPORTED";
		break;
	case 4004:
		response = "NOT_FOUND";
		break;
	case 4005:
		response = "OPERATION_NOT_ALLOWED";
		break;
	case 4008:
		response = "REQUEST_TIMEOUT";
		break;
	case 4101:
		response = "SUBSCRIPTION_CREATOR_HAS_NO_PRIVILEGE";
		break;
	case 4102:
		response = "CONTENTS_UNACCEPTABLE";
		break;
	case 4103:
		response = "ORIGINATOR_HAS_NO_PRIVILEGE";
		break;
	case 4104:
		response = "GROUP_REQUEST_IDENTIFIER_EXISTS";
		break;
	case 4105:
		response = "CONFLICT";
		break;
	case 4106:
		response = "ORIGINATOR_HAS_NOT_REGISTERED";
		break;
	case 4107:
		response = "SECURITY_ASSOCIATION_REQUIRED";
		break;
	case 4108:
		response = "INVALID_CHILD_RESOURCE_TYPE";
		break;
	case 4109:
		response = "NO_MEMBERS";
		break;
	case 4110:
		response = "GROUP_MEMBER_TYPE_INCONSISTENT";
		break;
	case 4111:
		response = "ESPRIM_UNSUPPORTED_OPTION";
		break;
	case 4112:
		response = "ESPRIM_UNKNOWN_KEY_ID";
		break;
	case 4113:
		response = "ESPRIM_UNKNOWN_ORIG_RAND_ID";
		break;
	case 4114:
		response = "ESPRIM_UNKNOWN_RECV_RAND_ID";
		break;
	case 4115:
		response = "ESPRIM_BAD_MAC";
		break;
	case 4116:
		response = "ESPRIM_IMPERSONATION_ERROR";
		break;
	case 4117:
		response = "ORIGINATOR_HAS_ALREADY_REGISTERED";
		break;
	case 4118:
		response = "ONTOLOGY_NOT_AVAILABLE";
		break;
	case 4119:
		response = "LINKED_SEMANTICS_NOT_AVAILABLE";
		break;
	case 4120:
		response = "INVALID_SEMANTICS";
		break;
	case 4121:
		response = "MASHUP_MEMBER_NOT_FOUND";
		break;
	case 4122:
		response = "INVALID_TRIGGER_PURPOSE";
		break;
	}
}
