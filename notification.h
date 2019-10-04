void notification (MQTTClient client){
		printf("\n In Notification Procedure\n");
		Request Req;
		Req.To = nu; //put AE_ID of the subscribed node 
		Req.From = CSE_ID;
		Req.Request_Identifier = "m_notify01";
		Req.Operation = 5;
		Ntfy.subscriptionReference = "/CSE01";
		Ntfy.notificationEventType = net;
		Ntfy.content = con;
		Ntfy.contentInfo = cnf;
		buf = Notify(Req);
		strcpy(AEID, From.c_str());
		//Set Topic to /oneM2M/req/SAE01/CSE_01
		create_Topic("resp", AEID, "CSE_01");
		//Publish Notify to 
		sleep(5);
		publish(client, buf.c_str());
			
		_notify = false;
		//wait for Notification Response
		rsc = 0;
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
		if(rsc == 2000)
			printf("Notification Done wth response: %s\n", response.c_str());
		else 
			printf("Notification failed with response: %s\n", response.c_str());
		return;
}
