#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "keymnglog.h"
#include "keymngserverop.h"
#include "poolsocket.h"
#include "keymng_msg.h"
#include "myipc_shm.h"
#include "keymng_shmop.h"
#include "icdbapi.h"
#include "keymng_dbop.h"

int MngServer_InitInfo(MngServer_Info *svrInfo)
{
    int ret = 0;
    printf("func MngServer_InitInfo() begin\n");

    //数据库的信息
    strcpy(svrInfo->dbuse, "SECMNG");
    strcpy(svrInfo->dbpasswd, "SECMNG");
    strcpy(svrInfo->dbsid, "orcl");    
    svrInfo->dbpoolnum = 20;

    strcpy(svrInfo->serverId, "0001");
    strcpy(svrInfo->serverip, "127.0.0.1");
    svrInfo->serverport = 8001;

    //共享内存文件信息
    svrInfo->maxnode = 30; 			
    svrInfo->shmkey  = 0x0001;
    svrInfo->shmhdl  = 0;
    
    //初始化连接池
    ret=IC_DBApi_PoolInit(svrInfo->dbpoolnum,svrInfo->dbsid,svrInfo->dbuse,svrInfo->dbpasswd);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_PoolInit error %d",ret);
    }
    else
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_PoolInit success");
    }


    //有则打开共享内存文件，无则创建
    ret=KeyMng_ShmInit(svrInfo->shmkey ,svrInfo->maxnode, &svrInfo->shmhdl);

    if(ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngserver KeyMng_ShmInit error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver KeyMng_ShmInit success");
    printf("func MngServer_InitInfo() ok\n");
    return ret;
}


//密钥协商
int MngServer_Agree(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{


    int   ret = 0;
    int   i   = 0;

    //检查参数是否合法，错误打日志
    if(svrInfo==NULL||msgkeyReq==NULL||outData==NULL||datalen==NULL)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"MngServer_Agree arguement error %d",ret);
        return KeyMng_ParamErr;//输入参数失败         
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"MngServer_Agree  arguement success");


    //定义应答报文结构体
    MsgKey_Res			msgKeyRes;    //clientID/ serverID / rv r2[] serkeyid
    msgKeyRes.rv=0;//返回值
    strcpy(msgKeyRes.clientId,msgkeyReq->clientId);
    strcpy(msgKeyRes.serverId,msgkeyReq->serverId);

    // 服务器产生随机码
    for (i=0; i<64; i++)
    {
        msgKeyRes.r2[i] = 'a'+i;
    }
    msgKeyRes.seckeyid = -1;


    //验证客户端请求报文的serverid 和 服务器端的serverid是否相同; 
    if(strcmp(svrInfo->serverId,msgkeyReq->serverId)!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],4,"msgkeyReq->serverId not euqal svrInfo->serverId ");
        msgKeyRes.rv = 111;
    }    


    //都成功了，才产生密钥对，并且写入共享内存
    if(msgKeyRes.rv==0)
    {

        ICDBHandle handle=NULL;           

        //从连接池中取一个连接
        ret=IC_DBApi_ConnGet(&handle,0,0);
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_ConnGet error ");
        }
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_ConnGet success");
        }

        //启动事务
        ret=IC_DBApi_BeginTran(handle);

        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_BeginTran error %d",ret);
        }
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_BeginTran success");
        }

        //获取keysn这个表中获取seckeyid
        ret=KeyMngsvr_DBOp_GenKeyID(handle,&msgKeyRes.seckeyid);
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"KeyMngsvr_DBOp_GenKeyID error %d",ret);
            
        }
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"KeyMngsve_DBOP_GenKeyID success");
        }

        //先将网点信息写到共享内存文件中
        NodeSHMInfo shminfo;
        memset(&shminfo,0,sizeof(shminfo));
        shminfo.status = 0;//状态
        strcpy(shminfo.clientId,msgkeyReq->clientId);
        strcpy(shminfo.serverId,msgkeyReq->serverId);
        shminfo.seckeyid = msgKeyRes.seckeyid;

        //产生密码
        for(i=0;i<64;i++)
        {
            shminfo.seckey[2*i]=msgkeyReq->r1[i];
            shminfo.seckey[2*i+1]=msgKeyRes.r2[i];    		  	
        }
        KeyMng_ShmWrite(svrInfo->shmhdl,svrInfo->maxnode,&shminfo);  


        //写入数据库
        ret=KeyMngsvr_DBOp_WriteSecKey(handle,&shminfo); 
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"KeyMngsvr_DBOp_WriteSecKey error %d",ret);
            IC_DBApi_Rollback(handle);//失败回滚
        }        
       
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"KeyMngsvr_DBOp_WriteSecKey success");
            IC_DBApi_Commit(handle); //成功提交
        }

        //将连接放回数据库
        if(ret==IC_DB_CONNECT_ERR)
        {
            IC_DBApi_ConnFree(handle,0);//需要修复
        }
        else
        {
            IC_DBApi_ConnFree(handle,1);//不需要修复
        }


    }

    //编码应答报文 
    ret=MsgEncode(&msgKeyRes,ID_MsgKey_Res,outData,datalen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MsgEncode  error %d",ret);
        return  ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MsgEncode success");

    return 0;
}

//密钥校验
int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
    int           ret = 0;
    int           i   = 0;
    NodeSHMInfo   pNodeInfo;//网点信息
    MsgKey_Res    msgKeyRes;

    //检查参数是否合法，错误打日志
    if(svrInfo==NULL||msgkeyReq==NULL||outData==NULL||datalen==NULL)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"MngServer_Check arguement error %d",ret);
        return KeyMng_ParamErr;//输入参数失败         
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"MngServer_Check  arguement success");

    ret=KeyMng_ShmRead(svrInfo->shmhdl,msgkeyReq->clientId,msgkeyReq->serverId,svrInfo->maxnode,&pNodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"MngServer_Check KeyMng_ShmRead error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"MngServer_Check KeyMng_ShmRead success");

    //定义应答报文
    memset(&msgKeyRes,0,sizeof(msgKeyRes));
    msgKeyRes.rv = 0;
    strcpy(msgKeyRes.clientId,msgkeyReq->clientId);
    strcpy(msgKeyRes.serverId,msgkeyReq->serverId);

    //随机数就是密钥对的前8个
    memcpy(msgKeyRes.r2,pNodeInfo.seckey,8);

    msgKeyRes.seckeyid = 0;

    //验证客户端请求报文的serverid 和 服务器端的serverid是否相同; 
    if(strcmp(svrInfo->serverId,msgkeyReq->serverId)!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],4,"msgkeyReq->serverId not euqal svrInfo->serverId ");
        msgKeyRes.rv = 111;
    }

    if(strncmp(msgKeyRes.r2,msgkeyReq->r1,8)!=0)
    {

        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],4,"msgkeyReq->r1not euqal msgKeyRes.r2 ");
        msgKeyRes.rv=222;

    }

    //编码应答报文 
    ret=MsgEncode(&msgKeyRes,ID_MsgKey_Res,outData,datalen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MsgEncode  error %d",ret);
        return  ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MsgEncode success");
    return 0;
}


//密钥注销
int MngServer_Revoke(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
    int           ret = 0;
    int           i   = 0;
    NodeSHMInfo   pNodeInfo;//网点信息
    MsgKey_Res    msgKeyRes;
   

    //检查参数是否合法，错误打日志
    if(svrInfo==NULL||msgkeyReq==NULL||outData==NULL||datalen==NULL)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"MngServer_Check arguement error %d",ret);
        return KeyMng_ParamErr;//输入参数失败         
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"MngServer_Check  arguement success");    
    
    //定义应答报文
    memset(&msgKeyRes,0,sizeof(msgKeyRes));
    msgKeyRes.rv = 0;
    strcpy(msgKeyRes.clientId,msgkeyReq->clientId);
    strcpy(msgKeyRes.serverId,msgkeyReq->serverId);
    memcpy(msgKeyRes.r2,pNodeInfo.seckey,8);
    msgKeyRes.seckeyid = 0;

    //验证客户端请求报文的serverid 和 服务器端的serverid是否相同; 
    if(strcmp(svrInfo->serverId,msgkeyReq->serverId)!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],4,"msgkeyReq->serverId not euqal svrInfo->serverId ");
        msgKeyRes.rv = 111;
    }
        
  
    if(msgKeyRes.rv==0)
    {
    	  //读共享内存文件
			  ret=KeyMng_ShmRead(svrInfo->shmhdl,msgkeyReq->clientId,msgkeyReq->serverId,svrInfo->maxnode,&pNodeInfo);
			  if(ret!=0)
			  {
			      KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"MngServer_Check KeyMng_ShmRead error %d",ret);
			      return ret;
			  }
			  KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"MngServer_Check KeyMng_ShmRead success");
			  
    	  //先将网点信息写到共享内存文件中       
        pNodeInfo.status = 1;//状态
        KeyMng_ShmWrite(svrInfo->shmhdl,svrInfo->maxnode,&pNodeInfo);  


        ICDBHandle handle=NULL;          

        //从连接池中取一个连接
        ret=IC_DBApi_ConnGet(&handle,0,0);
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_ConnGet error ");
        }
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_ConnGet success");
        }

        //启动事务       
        ret=IC_DBApi_BeginTran(handle);
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_BeginTran error %d",ret);
        }
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_BeginTran success");
        }
        
   
        
        //更新数据库信息
        ret=KeyMngsvr_DBOp_UpdateSecKey(handle,&pNodeInfo);   
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"IC_DBApi_ExecNSelSql error %d",ret);
            msgKeyRes.rv==222;
            IC_DBApi_Rollback(handle);//失败回滚
        }        
       
        else
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"IC_DBApi_ExecNSelSql success");
            IC_DBApi_Commit(handle); //成功提交
        }

        //将连接放回数据库
        if(ret==IC_DB_CONNECT_ERR)
        {
            IC_DBApi_ConnFree(handle,0);//需要修复
        }
        else
        {
            IC_DBApi_ConnFree(handle,1);//不需要修复
        }

    }
    
    //编码应答报文 
    ret=MsgEncode(&msgKeyRes,ID_MsgKey_Res,outData,datalen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MsgEncode  error %d",ret);
        return  ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MsgEncode success");
    return 0;
}
