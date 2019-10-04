//#pragma once
#include <string.h>
#include "resource.h"
#include "JSON.h"

void process_crt(MbedJSONValue& MSG, MbedJSONValue& MSG_1, MbedJSONValue& MSG_2);
void process_rsc(MbedJSONValue& MSG, MbedJSONValue& MSG_1);
void process_dlt(MbedJSONValue& MSG);
void process_updt(MbedJSONValue& MSG);
void process_retv(MbedJSONValue& MSG);

struct Resource RES;
struct regularResource regRES;
struct announceableResource ancRES;
struct announcedResource ancdRES;
struct subordinateResource subRES;
struct announceableSubordinateResource ancsubRES;
struct announcedSubordinateResource ancdsubRES;

struct CreateAE CAE;
struct respAE RAE;
struct respCnt RCnt;
struct respCin RCin;
struct respSub RSub;
struct notify Ntfy;

//extern const char* CSE_ID;
extern const char* AE_ID;
extern bool lcl;

//////////////////////////////////////////////
//      Func: Create_Req                    //
//      returns a json string               //
//      input parameters Class Request      //
//////////////////////////////////////////////
std::string Create_Req(Request Req)
{
	MbedJSONValue demo, demo2, demo3;

	std::string s;
	switch (Req.Resource_Type) {
	case 0:
		break;
	case 1:
		break;
	case 2:
		demo3["api"] = CAE.App_ID;
		demo3["rn"] = CAE.resourceName;
		demo3["rr"] = CAE.requestReachability;
		demo2["m2m:ae"] = demo3;
		break;
	case 3:
		demo3["rn"] = CAE.resourceName;
		demo2["m2m:cnt"] = demo3;
		break;
	case 4:
		break;
	}
	demo["fr"] = Req.From;
	demo["op"] = Req.Operation;
	demo["pc"] = demo2;
	demo["rqi"] = Req.Request_Identifier;
	demo["to"] = Req.To;
	demo["ty"] = Req.Resource_Type;
	demo["lcl"] = lcl;

	//serialize it into a JSON string
	s = demo.serialize();
	#ifdef debug
	printf("\nMSG SIZE: %d\n", s.length());
	printf("Req JSON: %s\r\n", s.c_str());
	#endif
	return s;
}
//////////////////////////////////////////////
//      Func: Notify	                    //
//      returns a json string               //
//      input parameters Class Response     //
//////////////////////////////////////////////
std::string Notify(Request Req)
{
	MbedJSONValue demo, demo2, demo3, demo4, demo5, demo6;
	std::string s;

	demo6["con"] = Ntfy.content;
	demo6["conf"] = Ntfy.contentInfo;

	demo5["cin"] = demo6;
	demo4["rep"] = demo5;
	demo4["net"] = Ntfy.notificationEventType;
	demo3["nev"] = demo4;
	demo3["sur"] = Ntfy.subscriptionReference;

	demo["fr"] = Req.From;
	demo["op"] = Req.Operation;
	demo2["m2m:sgn"] = demo3;
	demo["pc"] = demo2;
	

	demo["rqi"] = Req.Request_Identifier;
	demo["to"] = Req.To;
	//serialize it into a JSON string
	s = demo.serialize();
	#ifdef debug
	printf("\nMSG SIZE: %d\n", s.length());
	printf("Req JSON: %s\r\n", s.c_str());
	#endif
	return s;
}

//////////////////////////////////////////////
//      Func: Delete_Resp                   //
//      returns a json string               //
//      input parameters Class Response     //
//////////////////////////////////////////////
std::string Delete_Resp(Response Resp)
{
	MbedJSONValue demo;
	std::string s;
	demo["rsc"] = Resp.responseStatusCode;
	demo["rqi"] = Resp.Request_Identifier;
	demo["to"] = Resp.To;
	demo["fr"] = Resp.From;

	//serialize it into a JSON string
	s = demo.serialize();
	#ifdef debug
	printf("\nMSG SIZE: %d\n", s.length());
	printf("RESP JSON: %s\r\n", s.c_str());
	#endif
	return s;
}

//////////////////////////////////////////////
//      Func: Retrive_Resp                  //
//      returns a json string               //
//      input parameters Class Response     //
//////////////////////////////////////////////
std::string Retrive_Resp(Response Resp)
{
	MbedJSONValue demo, demo2, demo3;
	std::string s;
	demo["rsc"] = Resp.responseStatusCode;
	demo["rqi"] = Resp.Request_Identifier;
	if(aei != "NULL"){
		demo3["api"] = api;
		demo3["rn"] = rn;
		demo3["rr"] = rr;
		demo2["m2m:ae"] = demo3;
	}
	demo["to"] = Resp.To;
	demo["fr"] = Resp.From;
	demo["pc"] = demo2;
	
	//serialize it into a JSON string
	s = demo.serialize();
	printf("\nMSG SIZE: %d\n", s.length());
	printf("RESP JSON: %s\r\n", s.c_str());
	return s;
}

std::string Retrive_Req(Request Req){
	MbedJSONValue demo;
	std::string s;
	demo["op"] = Req.Operation;
	demo["rqi"] = Req.Request_Identifier;
	demo["to"] = Req.To;
	demo["fr"] = Req.From;
	
	//serialize it into a JSON string
	s = demo.serialize();
	#ifdef debug
	printf("\nMSG SIZE: %d\n", s.length());
	printf("RESP JSON: %s\r\n", s.c_str());
	#endif
	return s;
}

//////////////////////////////////////////////
//      Func: Create_Resp                   //
//      returns a json string               //
//      input parameters Class Response     //
//////////////////////////////////////////////
std::string Create_Resp(Response Resp)
{
	MbedJSONValue demo, demo2, demo3, demo4;
	demo3["ty"] = RES.Resource_Type;
	demo3["ri"] = RES.resourceID;
	demo3["pi"] = RES.parentID;
	demo3["ct"] = RES.creationTime;         //ct     1
	demo3["lt"] = RES.lastModifiedTime;     //lt     1  
	demo3["rn"] = RES.resourceName;
	std::string s;
	switch (RES.Resource_Type) {
	case 0:
		demo3["api"] = RAE.App_ID;
		demo3["rr"] = RAE.requestReachability;
		demo3["aei"] = RAE.AE_ID;
		demo3["poa"] = RAE.pointOfAccess;
		demo2["m2m:ae"] = demo3;
		break;
	case 1:
		break;
	case 2:
		demo3["api"] = RAE.App_ID;
		demo3["rr"] = RAE.requestReachability;
		demo3["aei"] = RAE.AE_ID;
		demo3["poa"] = RAE.pointOfAccess;
		demo2["m2m:ae"] = demo3;
		break;
	case 3:
		demo3["st"] = RCnt.stateTag;
		demo3["cni"] = RCnt.CurrentNrOfInstances;
		demo3["cbs"] = RCnt.CurrentByteSize;
		demo2["m2m:cnt"] = demo3;
		break;
	case 4:
		demo3["et"] = ancsubRES.expirationTime;
		demo3["st"] = RCin.stateTag;
		demo3["cnf"] = RCin.contentInfo;
		demo3["cs"] = RCin.contentSize;
		demo3["con"] = RCin.content;
		demo2["m2m:cin"] = demo3;
		break;
	case 23:
		demo3["et"] = ancsubRES.expirationTime;
		demo4["net"] = RSub.notificationEventType;
		demo3["enc"] = demo4;
		demo3["nct"] = RSub.notificationContentType;
		demo3["nu"] = RSub.notificationURI;
		demo2["m2m:sub"] = demo3;
		break;

	}
	demo["rsc"] = Resp.responseStatusCode;
	demo["rqi"] = Resp.Request_Identifier;
	demo["pc"] = demo2;
	demo["to"] = Resp.To;
	demo["fr"] = Resp.From;

	//serialize it into a JSON string
	s = demo.serialize();
	#ifdef debug
	printf("\nMSG SIZE: %d\n", s.length());
	printf("RESP JSON: %s\r\n", s.c_str());
	#endif
	return s;
}

void process_msg(const char* Buffer)
{
	MbedJSONValue MSG, MSG_1, MSG_2;
	#ifdef debug
	printf("\nBuffer in process msg: %s\n", Buffer);
	#endif
	parse(MSG, Buffer);

	
	////////////////////////Response Status Code//////////////////////
	
	if (MSG.hasMember("rsc"))
	{
		rsc = MSG["rsc"].get<int>();
		printf("Response Status Code: %d\r\n", rsc);
		Response_Type();
		printf("Response Status: %s\r\n", response.c_str());
		MSG_1 = MSG["pc"][content];
		process_rsc(MSG, MSG_1);
		return;
	}
	
	////////////////////////To Parameter (Mendatory parameter)//////////////////////
	
	if (MSG.hasMember("to"))
	{
		to = MSG["to"].get<std::string>();
		char *str_tok;
		char* temp1 = new char[to.length() +1];
		strcpy(temp1, to.c_str());
		str_tok = strtok (temp1, "/");
		while (str_tok != NULL)
		{
			_to = str_tok;
			printf("\nto:%s\n", _to);
			str_tok = strtok(NULL, "/");
		}
		printf("To: %s\r\n", to.c_str());
		delete temp1;
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}
	////////////////////////From parameter (Mendatory parameter[optional for Create AE])//////////
	
	if (MSG.hasMember("fr"))
	{
		From = MSG["fr"].get<std::string>();
		printf("From: %s\r\n", From.c_str());
	}
	else {
		rsc = 4000;			//Response Status Code for no mendatory parameter BAD_REQUEST 
		return;
	}
	////////////////////////Request Identifier (Mendatory parameter)//////////////////////
	
	if (MSG.hasMember("rqi"))
	{
		rqi = MSG["rqi"].get<std::string>();
		printf("Request Identifier: %s\r\n", rqi.c_str());
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}
	////////////////////////Operation Parameter (Mendatory parameter)//////////////////////
	
	if (MSG.hasMember("op"))
	{
		op = MSG["op"].get<int>();
		printf("Operation: %d\r\n", op);
		Operation_Type();
		printf("Operation: %s\r\n", operation.c_str());
		if (op == 4){
			process_dlt(MSG);
			goto exit;
		}
		if (op == 3){
			process_updt(MSG);
			goto exit;
		}
		if (op == 2){
			process_retv(MSG);
			goto exit;
		}
		if (op == 1){
			process_crt(MSG, MSG_1, MSG_2);
			goto exit;
		}
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}
	
	exit:
	MSG.~MbedJSONValue();
	MSG_1.~MbedJSONValue();
	return;
}

void process_crt(MbedJSONValue& MSG, MbedJSONValue& MSG_1, MbedJSONValue& MSG_2)
{
	
	////////////////////////resource Type Parameter (Mendatory parameter)//////////////////////

	if (MSG.hasMember("ty"))
	{
		ty = MSG["ty"].get<int>();
		#ifdef debug 
		printf("ResourceType: %d\r\n", ty);
		#endif
		resource_type();
		printf("ResourceType: %s\r\n", resourceType.c_str());
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}

	MSG_1 = MSG["pc"][content]; //content value depends on the resource type e.g. m2m:ae for resource type 2

	//////////////////////// Resource specific attributes CSE-ID
	
	if (MSG_1.hasMember("csi"))
	{
		csi = MSG_1["csi"].get<std::string>();
		printf("CSI: %s\r\n", csi.c_str());
	}

	//////////////////////// Resource specific attributes Point of Access
	
	if (MSG_1.hasMember("poa"))
	{
		poa = MSG_1["poa"].get<std::string>();
		printf("POA: %s\r\n", poa.c_str());
	}

	/////////////////////// Resource specific attributes CSE Type
	
	if (MSG_1.hasMember("cst"))
	{
		cst = MSG_1["cst"].get<int>();
		#ifdef debug 
		printf("CSE Type: %d\r\n", cst);
		#endif
		CSE_Type();
		printf("CSE Type: %s\r\n", cseType.c_str());
	}

	/////////////////////// Resource specific attributes RequestReachability
	
	if (MSG_1.hasMember("rr"))
	{
		rr = MSG_1["rr"].get<bool>();
		printf("RR: %s\r\n", rr ? "true" : "false");
	}

	/////////////////////// Resource specific attributes App-ID
	
	if (MSG_1.hasMember("api"))
	{
		api = MSG_1["api"].get<std::string>();
		printf("App-ID: %s\r\n", api.c_str());
	}
	/////////////////////// Resource specific attributes resourceName
	
	if (MSG_1.hasMember("rn"))
	{
		rn = MSG_1["rn"].get<std::string>();
		printf("resourceName : %s\r\n", rn.c_str());
	}
	/////////////////////// Resource specific attributes Content
	
	if (MSG_1.hasMember("con"))
	{
		con = MSG_1["con"].get<std::string>();
		printf("Content: %s\r\n", con.c_str());
	}
	/////////////////////// Resource specific attributes ContentInfo
	
	if (MSG_1.hasMember("cnf"))
	{
		cnf = MSG_1["cnf"].get<std::string>();
		printf("Content Info: %s\r\n", cnf.c_str());
	}
	/////////////////////// Resource specific attributes NotificationURI nu
	
	if (MSG_1.hasMember("nu"))
	{
		nu = MSG_1["nu"].get<std::string>();
		printf("Notification URI: %s\r\n", nu.c_str());
	}
	/////////////////////// Resource specific attributes NotificationContentType
	
	if (MSG_1.hasMember("nct"))
	{
		nct = MSG_1["nct"].get<int>();
		printf("NotificationContentType: %d\r\n", nct);
		MSG_2 = MSG["pc"]["m2m:sub"]["enc"];

		if (MSG_2.hasMember("net"))
		{
			net = MSG_2["net"].get<int>();
			printf("NotificationEventType: %d\r\n", net);
		}
		MSG_2.~MbedJSONValue();
	}

	return;
}
void process_dlt(MbedJSONValue& MSG)
{
	printf("\nIn delete process\n");
	
	return;
}

void process_updt(MbedJSONValue& MSG)
{
	printf("\nIn Update process\n");
	///Content pc
	
	return;
}

void process_retv(MbedJSONValue& MSG)
{
	printf("\nIn Retrive process\n");
	
	return;
}

void process_rsc(MbedJSONValue& MSG, MbedJSONValue& MSG_1)
{
	if (MSG.hasMember("rqi"))
	{
		rqi = MSG["rqi"].get<std::string>();
		printf("Request Identifier: %s\r\n", rqi.c_str());
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}
	
	if (MSG.hasMember("to"))
	{
		to = MSG["to"].get<std::string>();
		printf("To: %s\r\n", to.c_str());
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}

	if (MSG.hasMember("fr"))
	{
		From = MSG["fr"].get<std::string>();
		printf("From: %s\r\n", From.c_str());
	}
	else {
		rsc = 4000;			//response code for no mendatory parameter
		return;
	}
	printf("Content: %s\r\n", content);
	

	if (MSG_1.hasMember("ty"))
	{
		ty = MSG_1["ty"].get<int>();
		printf("ResourceType in response: %d\r\n", ty);
	}
	else {
		//rsc = 4000;			//response code for no mendatory parameter
		return;
	}

	if (MSG_1.hasMember("rr"))
	{
		RequestReachability = MSG_1["rr"].get<bool>();
		printf("RR: %s\r\n", RequestReachability ? "true" : "false");
	}

	if (MSG_1.hasMember("aei"))
	{
		aei = MSG_1["aei"].get<std::string>();
		printf("AE_ID: %s\r\n", aei.c_str());
	}

	if (MSG_1.hasMember("poa"))
	{
		poa = MSG_1["poa"].get<std::string>();
		printf("POA: %s\r\n", poa.c_str());
	}

	if (MSG_1.hasMember("rn"))
	{
		rn = MSG_1["rn"].get<std::string>();
		printf("Resource Name: %s\r\n", rn.c_str());
	}

	if (MSG_1.hasMember("api"))
	{
		api = MSG_1["api"].get<std::string>();
		printf("App-ID: %s\r\n", api.c_str());
	}
	/////////////////////// Resource specific attributes Content

	if (MSG_1.hasMember("con"))
	{
		con = MSG_1["con"].get<std::string>();
		printf("Content: %s\r\n", con.c_str());
	}
	/////////////////////// Resource specific attributes ContentInfo

	if (MSG_1.hasMember("cnf"))
	{
		cnf = MSG_1["cnf"].get<std::string>();
		printf("Content Info: %s\r\n", cnf.c_str());
	}

	return;
}
