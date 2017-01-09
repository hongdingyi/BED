#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "keymngserverop.h"
#include "poolsocket.h"
#include "keymnglog.h"


MngServer_Info svrInfo;

#define Sck_ErrParam                	    (Sck_BaseErr+1)
#define Sck_ErrTimeOut                    (Sck_BaseErr+2)
#define Sck_ErrPeerClosed                 (Sck_BaseErr+3)
#define Sck_ErrMalloc			   	            (Sck_BaseErr+4)

int flag=0;
int init_daemon()
{
    int i;
    int pid;
    int fd=open("/dev/null",O_WRONLY);
    dup2(fd,1);
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
    signal(SIGCHLD,SIG_IGN);
    if(pid=fork())
    {
        exit(0);
    }
    setsid();
    if(pid=fork())
    {
        exit(0);
    }
    umask(0);
    chdir("/");
    return 0;	 	
}

void *handle(void *arg)
{
    int             connfd = (int)arg;
    int             ret;
    int             timeout = 3;
    int             inLen = 0;
    int             outLen;
    int             type;
    int             cmdtype;  
    unsigned char*  outData = NULL;
    unsigned char*  inData = NULL;
    MsgKey_Req*     msgkeyReq = NULL;

    while(1)
    { 
        if(flag==1)
            break;
        //接收客户端数据
        ret=sckServer_rev(connfd,timeout,&outData,&outLen);  
        if(ret==Sck_ErrTimeOut)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngserver sckServer_rev Sck_ErrTimeOut error %d",ret);
            continue;
        }

        if(ret==Sck_ErrParam)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_rev Sck_ErrParam error %d",ret);
            break;
        }

        if(ret==Sck_ErrPeerClosed )
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_rev Sck_ErrPeerClosed error %d",ret);
            if(outData!=NULL)
            {
                sck_FreeMem(&outData);
            }
            break;
        }
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver sckServer_rev success");

        //解码客户端的请求报文
        ret=MsgDecode(outData,outLen,&msgkeyReq,&type);
        if(ret!=0)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MsgDecode error %d",ret);
            if(outData!=NULL)sck_FreeMem(&outData);
            break;
        }
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MsgDecode success");

        //处理客户端响应的业务
        cmdtype=msgkeyReq->cmdType;       

        switch(cmdtype)
        {
                //密钥协商
            case KeyMng_NEWorUPDATE:
                {
                    ret=MngServer_Agree(&svrInfo,msgkeyReq,&inData, &inLen);
                    if(ret!=0)
                    {
                        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MngServer_Agree error%d",ret);
                        if(outData!=NULL)    sck_FreeMem(&outData);
                        if(msgkeyReq!=NULL)  MsgMemFree(&msgkeyReq,type);
                        return ret;
                    }
                    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MngServer_Agree success");
                }                	
                break;

                //密钥校验
            case KeyMng_Check:
                {
                    ret=MngServer_Check(&svrInfo,msgkeyReq,&inData, &inLen);
                    if(ret!=0)
                    {
                        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MngServer_Check error%d",ret);
                        if(outData!=NULL)    sck_FreeMem(&outData);
                        if(msgkeyReq!=NULL)  MsgMemFree(&msgkeyReq,type);
                        return ret;
                    }
                    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MngServer_Check success");
                }                	
                break;
                
                 //密钥注销
            case KeyMng_Revoke:
                {
                    ret=MngServer_Revoke(&svrInfo,msgkeyReq,&inData, &inLen);
                    if(ret!=0)
                    {
                        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver MngServer_Revoke error%d",ret);
                        if(outData!=NULL)    sck_FreeMem(&outData);
                        if(msgkeyReq!=NULL)  MsgMemFree(&msgkeyReq,type);
                        return ret;
                    }
                    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver MngServer_Revoke success");
                }                	
                break;
                

            default:
                break;
        }

        //发送应答报文给客户端
        ret=sckServer_send(connfd,timeout,inData,inLen);

        if(ret==Sck_ErrTimeOut)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngserver sckServer_send Sck_ErrTimeOut error %d",ret);
            //释放内存
            if(outData!=NULL)   sck_FreeMem(&outData);
            if(msgkeyReq!=NULL) MsgMemFree(&inData,0);
            if(msgkeyReq!=NULL) MsgMemFree(&msgkeyReq,type);
            continue;
        }

        if(ret==Sck_ErrParam)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_send Sck_ErrParam error %d",ret);
            //释放内存
            if(outData!=NULL)   sck_FreeMem(&outData);
            if(msgkeyReq!=NULL) MsgMemFree(&inData,0);
            if(msgkeyReq!=NULL) MsgMemFree(&msgkeyReq,type);
            break;
        }

        if(ret==Sck_ErrPeerClosed )
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_send Sck_ErrPeerClosed error %d",ret);
            //释放内存
            if(outData!=NULL)   sck_FreeMem(&outData);
            if(msgkeyReq!=NULL) MsgMemFree(&inData,0);
            if(msgkeyReq!=NULL) MsgMemFree(&msgkeyReq,type);
            break;
        }
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver sck_FreeMem success");

        //释放内存
        if(outData!=NULL)   sck_FreeMem(&outData);
        if(msgkeyReq!=NULL) MsgMemFree(&inData,0);
        if(msgkeyReq!=NULL) MsgMemFree(&msgkeyReq,type);

    }
    sckServer_close(connfd);
}
//信号处理函数
void dealsignal(int arg)
{
    flag=1;
}
int main()
{

    init_daemon();//启动守护进程
    signal(SIGUSR2,dealsignal);

    int       ret;
    int       listenfd;
    int       connfd;
    int       timeout = 3;
    pthread_t pid;

    //初始化服务器基本信息
    MngServer_InitInfo(&svrInfo);

    //初始化socket
    ret=sckServer_init(svrInfo.serverport,&listenfd);

    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_init error %d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2 ,"keymngserver sckServer_init success");

    while(1)
    {
        if(flag==1)
        {
            break;
        }
        ret=sckServer_accept(listenfd,timeout,&connfd);
        if(ret== Sck_ErrTimeOut )
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"keymngserver sckServer_accept Sck_ErrTimeOut error %d",ret);

            continue;
        }
        if(ret==Sck_ErrParam)
        {
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret ,"keymngserver sckServer_accept Sck_ErrParam error %d",ret);
            break;
        }
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"keymngserver sckServer_accept  success");

        pthread_create(&pid,NULL,handle,(void *)connfd);
        pthread_detach(pid);//分离线程
    }

    //服务器端环境释放 
    sckServer_destroy();	

    //释放数据库连接池
    IC_DBApi_PoolFree(); 

    return 0;
}
