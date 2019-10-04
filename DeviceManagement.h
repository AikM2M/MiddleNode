void DeviceManagement(MQTTClient client){
	Request Req;
	Req.To = to; //put AE_ID of the subscribed node 
	Req.From = CSE_ID;
	Req.Request_Identifier = "1235";
	Req.Operation = 5;
	buf = Retrive_Req(Req);
	strcpy(AEID, From.c_str());
	//Publish req to Sensor Node 
	create_Topic("req", to1[1], "CSE_01");
	sleep(5);
	publish(client, buf.c_str());
	    
	MGOJB = false;
	//wait for Notification Response
	rsc = 0;
	if(!Restart){
	    while(1)
	    {
		if(isMessageArrived)
		{
		    process_msg(messageBuffer);
		    isMessageArrived = false;
		    if(rsc != 0){ 
			//reg_resp = true;
			printf("rsc = %d\n",rsc);
			break;
		    }
		}
	    }
	    // PUBLISH that response to the Mobile Node
	    //Set Topic to /oneM2M/resp/--/CSE_01
	    create_Topic("resp", (char*)From.c_str(), "CSE_01");
	    sleep(2);
	    publish(client, buf.c_str());
	}
	
	if(rsc == 2000)
	    printf("Device Management Done wth response: %s\n", response.c_str());
	else 
	    printf("Device Management failed with response: %s\n", response.c_str());
	return;
}
