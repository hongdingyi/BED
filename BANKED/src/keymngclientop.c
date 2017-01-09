#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "keymng_msg.h"
#include "poolsocket.h"
#include "keymnglog.h"
#include "keymngclientop.h"
#include "keymng_shmop.h"
#include "myipc_shm.h"


int MngClient_InitInfo(MngClient_Info *pCltInfo)
{
    int ret = 0;
    strcpy(pCltInfo->clientId,"1111");//客户端编号
    strcpy(pCltInfo->AuthCode,"1111");//认证码
    strcpy(pCltInfo->serverId,"0001");//服务器编码
    strcpy(pCltInfo->serverip,"127.0.0.1");//服务器ip
    pCltInfo->serverport=8001;

    pCltInfo->maxnode =  1;//最大网点
    pCltInfo->shmkey  =  0x666;//共享内存文件的key
    pCltInfo->shmhdl  =  0;//共享内存文件的句柄

    //打开或创建客户端的共享内存文件
    ret=KeyMng_ShmInit(pCltInfo->shmkey ,pCltInfo->maxnode, &pCltInfo->shmhdl);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient KeyMng_ShmInit error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngclient KeyMng_ShmInit success");
    return 0;	
}

//密钥协商
int MngClient_Agree(MngClient_Info *pCltInfo)
{  
    int 			      mytime = 3;
    int 			      connfd = 0;  
    int 			      ret = 0;
    int             i = 0;
    int				      outLen = 0;	
    int			        msgKeyResDataLen = 0;
    int 			      iMsgKeyResTag = 0;
    unsigned char*  outData = NULL ;
    unsigned char*  msgKeyResData = NULL;  

    MsgKey_Res*           pMsgKeyRes = NULL;//应答报文		
    MsgKey_Req 	          msgKeyReq;//请求报文

    memset(&msgKeyReq, 0, sizeof(MsgKey_Req));
    msgKeyReq.cmdType=KeyMng_NEWorUPDATE;
    strcpy(msgKeyReq.clientId,pCltInfo->clientId);
    strcpy(msgKeyReq.AuthCode,pCltInfo->AuthCode);
    strcpy(msgKeyReq.serverId,pCltInfo->serverId);

    // 产生客户端随机码
    for (i=0; i<64; i++)
    {
        msgKeyReq.r1[i] = 'a' + i; 
    }

    //编码请求报文
    ret=MsgEncode(&msgKeyReq,ID_MsgKey_Req,&outData,&outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient MsgEncode error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgEncode success");

    //初始化socet
    ret=sckClient_init();    
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_init error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_init  success");

    //连接服务器
    ret=sckClient_connect(pCltInfo->serverip,pCltInfo->serverport,mytime,&connfd);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_connect error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_connect  success");

    //发送请求报文
resend:
    ret=sckClient_send(connfd,mytime,outData,outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_send error %d",ret);
        goto resend;//重发

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_send  success");


    //接收应答报文		
    ret=sckClient_rev(connfd,mytime,&msgKeyResData,&msgKeyResDataLen );	
    if(ret!=0)//接收失败
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_rev error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_rev success");

    //客户端解码应答报文
    ret=MsgDecode(msgKeyResData,msgKeyResDataLen,(void **)&pMsgKeyRes,&iMsgKeyResTag);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngclient MsgDecode error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgDecode success");

    //协商失败
    if(pMsgKeyRes->rv!=0||pMsgKeyRes->seckeyid<0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"pMsgKeyRes->rv error %d",ret);
        ret=111;
        goto Start_MyFree;
    }

    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"pMsgKeyRes->rv success");


    //协商成功，才产生密钥对，并且写入共享内存
    NodeSHMInfo shminfo;
    memset(&shminfo,0,sizeof(shminfo));
    shminfo.status=0;
    strcpy(shminfo.clientId,pCltInfo->clientId);
    strcpy(shminfo.serverId,pCltInfo->serverId);
    shminfo.seckeyid= pMsgKeyRes->seckeyid;

    //生成密钥对
    for(i=0;i<64;i++)
    {
        shminfo.seckey[2*i]=msgKeyReq.r1[i];
        shminfo.seckey[2*i+1]=pMsgKeyRes->r2[i];    		  	
    }

    KeyMng_ShmWrite(pCltInfo->shmhdl,pCltInfo->maxnode,&shminfo);
    printf("seckeyid = %d\n",pMsgKeyRes->seckeyid);

    //释放内存
Start_MyFree:
    sckClient_closeconn(connfd);
    if(outData!=NULL)
    {
        MsgMemFree(&outData,0);
    }
    if(msgKeyResData!=NULL)
    {
        sck_FreeMem(&msgKeyResData);
    }
    if(pMsgKeyRes!=NULL)
    {
        MsgMemFree(&pMsgKeyRes, ID_MsgKey_Res);
    }		
    sckClient_destroy();
    return ret;

}

//密钥校验
int MngClient_Check(MngClient_Info *pCltInfo)
{
    int             mytime = 3;
    int             connfd = 0;
    int             outLen = 0;
    int             ret = 0;
    int             msgKeyResDataLen = 0;
    int             iMsgKeyResTag = 0;
    unsigned char*  outData = NULL;
    unsigned char*  msgKeyResData = NULL;
    NodeSHMInfo     pNodeInfo;
    MsgKey_Req 	    msgKeyReq;	
    MsgKey_Res*     pMsgKeyRes = NULL;

    //从共享内存中读取内容
    ret=KeyMng_ShmRead(pCltInfo->shmhdl,pCltInfo->clientId,pCltInfo->serverId,pCltInfo->maxnode,&pNodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient KeyMng_ShmRead error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient KeyMng_ShmRead success");

    //组织请求报文
    memset(&msgKeyReq, 0, sizeof(MsgKey_Req));
    msgKeyReq.cmdType=KeyMng_Check;
    strcpy(msgKeyReq.clientId,pCltInfo->clientId);
    strcpy(msgKeyReq.AuthCode,pCltInfo->AuthCode);
    strcpy(msgKeyReq.serverId,pCltInfo->serverId);
    strncpy(msgKeyReq.r1,pNodeInfo.seckey,8);//密钥对的前八位

    printf("客户端取出来的密钥前八位为:%s\n",msgKeyReq.r1);  

    //编码请求报文
    ret=MsgEncode(&msgKeyReq,ID_MsgKey_Req,&outData,&outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient MsgEncode error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgEncode success");


    //初始化socket
    ret=sckClient_init();    
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_init error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_init  success");

    //连接服务器
    ret=sckClient_connect(pCltInfo->serverip,pCltInfo->serverport,mytime,&connfd);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_connect error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_connect  success");

    //发送请求报文
resend:
    ret=sckClient_send(connfd,mytime,outData,outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_send error %d",ret);
        goto resend;//重发

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_send  success");


    //接收应答报文		
    ret=sckClient_rev(connfd,mytime,&msgKeyResData,&msgKeyResDataLen );	
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_rev error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_rev success");

    //解码应答报文
    ret=MsgDecode(msgKeyResData,msgKeyResDataLen,(void **)&pMsgKeyRes,&iMsgKeyResTag);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngclient MsgDecode error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgDecode success");

    //校验失败
    if(pMsgKeyRes->rv!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"pMsgKeyRes->rv error %d",ret);
        ret=111;
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"pMsgKeyRes->rv success");
    printf("密钥校验成功\n");

    //释放内存
Start_MyFree:
    sckClient_closeconn(connfd);
    if(outData!=NULL)
    {
        MsgMemFree(&outData,0);
    }
    if(msgKeyResData!=NULL)
    {
        sck_FreeMem(&msgKeyResData);
    }

    if(pMsgKeyRes!=NULL)
    {
        MsgMemFree(&pMsgKeyRes, ID_MsgKey_Res);
    }		
    sckClient_destroy();
    return ret;

}


//密钥注销
int MngClient_Revoke(MngClient_Info *pCltInfo)
{
    int             mytime = 3;
    int             connfd = 0;
    int             outLen = 0;
    int             ret = 0;
    int             msgKeyResDataLen = 0;
    int             iMsgKeyResTag = 0;
    unsigned char*  outData = NULL;
    unsigned char*  msgKeyResData = NULL;
    NodeSHMInfo     pNodeInfo;
    MsgKey_Req 	    msgKeyReq;	
    MsgKey_Res*     pMsgKeyRes = NULL;

    //从共享内存中读取内容
    ret=KeyMng_ShmRead(pCltInfo->shmhdl,pCltInfo->clientId,pCltInfo->serverId,pCltInfo->maxnode,&pNodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient KeyMng_ShmRead error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient KeyMng_ShmRead success");

    printf("-----pNodeInfo.status=%d------\n",pNodeInfo.status);
    //密钥已经被注销
    if(pNodeInfo.status==1)
    {
        printf("该密钥已被注销，密钥注销失败!\n");
        ret=111;
        return ret;
    }    		

    //组织请求报文
    memset(&msgKeyReq, 0, sizeof(MsgKey_Req));
    msgKeyReq.cmdType=KeyMng_Revoke;
    strcpy(msgKeyReq.clientId,pCltInfo->clientId);
    strcpy(msgKeyReq.AuthCode,pCltInfo->AuthCode);
    strcpy(msgKeyReq.serverId,pCltInfo->serverId);
    strncpy(msgKeyReq.r1,pNodeInfo.seckey,8);



    //编码请求报文
    ret=MsgEncode(&msgKeyReq,ID_MsgKey_Req,&outData,&outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient MsgEncode error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgEncode success");


    //初始化socket
    ret=sckClient_init();    
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_init error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_init  success");

    //连接服务器
    ret=sckClient_connect(pCltInfo->serverip,pCltInfo->serverport,mytime,&connfd);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_connect error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_connect  success");

    //发送请求报文
resend:
    ret=sckClient_send(connfd,mytime,outData,outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_send error %d",ret);
        goto resend;//重发

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_send  success");


    //接收应答报文		
    ret=sckClient_rev(connfd,mytime,&msgKeyResData,&msgKeyResDataLen );	
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"sckClient_rev error %d",ret);
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"sckClient_rev success");

    //解码应答报文
    ret=MsgDecode(msgKeyResData,msgKeyResDataLen,(void **)&pMsgKeyRes,&iMsgKeyResTag);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngclient MsgDecode error %d",ret);        
        goto Start_MyFree;

    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient MsgDecode success");

    //注销失败
    if(pMsgKeyRes->rv!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"pMsgKeyRes->rv error %d",ret);
        printf("密钥注销失败!\n");
        ret=111;
        goto Start_MyFree;

    }

    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"pMsgKeyRes->rv success");
    printf("密钥注销成功\n");

    //密钥注销成功后写入共享内存
    pNodeInfo.status=1;
    KeyMng_ShmWrite(pCltInfo->shmhdl,pCltInfo->maxnode,&pNodeInfo);


    //释放内存
Start_MyFree:
    sckClient_closeconn(connfd);
    if(outData!=NULL)
    {
        MsgMemFree(&outData,0);
    }
    if(msgKeyResData!=NULL)
    {
        sck_FreeMem(&msgKeyResData);
    }

    if(pMsgKeyRes!=NULL)
    {
        MsgMemFree(&pMsgKeyRes, ID_MsgKey_Res);
    }		
    sckClient_destroy();
    return ret;

}

//密钥查看
int MngClient_View(MngClient_Info *pCltInfo)
{
    int ret=0;
    NodeSHMInfo pNodeInfo;
    memset(&pNodeInfo,0,sizeof(pNodeInfo));

    ret=KeyMng_ShmRead(pCltInfo->shmhdl,pCltInfo->clientId,pCltInfo->serverId,pCltInfo->maxnode, &pNodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngclient KeyMng_ShmRead error %d",ret);
        printf("密钥查看失败\n");
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngclient KeyMng_ShmRead success");
    printf("密钥查看成功，以下是密钥具体信息\n");
    printf("status=%d\n",pNodeInfo.status);
    printf("clientId=%s\n",pNodeInfo.clientId);
    printf("serverId=%s\n",pNodeInfo.serverId);
    printf("serkeyid=%d\n",pNodeInfo.seckeyid);
    char view[1024]={0};
    memcpy(view,pNodeInfo.seckey,8);
    printf("密钥前八位为%s\n",view);
    return ret;
}
