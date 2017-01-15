#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "keymng_dbop.h"
#include "keymngserverop.h"
#include "keymnglog.h"
#include "icdbapi.h"

//读keysn 
int KeyMngsvr_DBOp_GenKeyID(void *dbhdl, int *keyid)
{
    int 			ret = 0;
    int 			ikeysn;

    ICDBRow     	row;
    ICDBField   	field[7];

    char			mysql1[1024];
    char			mysql2[1024];

    memset(field, 0, sizeof(field));
    memset(mysql1, 0, sizeof(mysql1));   
    memset(mysql2, 0, sizeof(mysql2));   

    if (dbhdl== NULL || keyid==NULL)
    {
        ret = -1;
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func KeyMngsvr_DBOp_GenKeyID() err");
        goto END;
    }

    sprintf(mysql1, "select ikeysn from SECMNG.KEYSN for update ");//使用sql锁 for update  
    printf("KeyMngsvr_DBOp_GenKeyID success\n");

    // 读取密钥序列号
    field[0].cont = (char *)&ikeysn;

    row.field = field;
    row.fieldCount = 1;		//只获取一列(一个域)


    ret =  IC_DBApi_ExecSelSql(dbhdl, mysql1, &row); //执行select语言   
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IC_DBApi_ExecSelSql() err,\n sql:%s", mysql1);
        printf("IC_DBApi_ExecSelSql error\n");
        goto END;	
    }	

    // 序列号加1 
    sprintf(mysql2,"update SECMNG.KEYSN set ikeysn = ikeysn + 1"); 
    printf("IC_DBApi_ExecSelSql success\n");

    ret =  IC_DBApi_ExecNSelSql(dbhdl, mysql2); //执行单个非select语言
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IC_DBApi_ExecNSelSql() err, sql:%s", mysql2);
        goto END;
    }
    printf("IC_DBApi_ExecNSelSql success\n");
    *keyid = ikeysn;   
END:

    return ret;
}

int KeyMngsvr_DBOp_WriteSecKey(void *dbhdl, NodeSHMInfo *pNodeInfo) 
{
    int       ret = 0;
    char      mysql[2048] = {0};

    char      optime[24] = {0};
    char	  tmpseckey2[1024];
    int		  tmplen = 1024;

    memset(tmpseckey2, 0, sizeof(tmpseckey2));
    memset(mysql, 0, sizeof(mysql));

    // 获取当前操作时间
    ret = IC_DBApi_GetDBTime(dbhdl, optime);
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IC_DBApi_GetDBTime() err");
        goto END;
    }

    // varchar2 4096 //oracle9  
    ret = IC_DBApi_Der2Pem(pNodeInfo->seckey, sizeof(pNodeInfo->seckey) , tmpseckey2, &tmplen );
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IC_DBApi_Der2Pem() err\n");
        goto END;
    }
    printf("tmpseckey:%s \n", tmpseckey2);
    printf("tmplen:%d \n", tmplen);

    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], ret, "\ntmpseckey===>%s \n tmplen===>%d\n", tmpseckey2, tmplen);

    //组织sql语句
    sprintf(mysql, "Insert Into SECMNG.SECKYEINFO(clientid, serverid, keyid, createtime, state, seckey) \
            values ('%s', '%s', %d, '%s', %d, '%s') ", pNodeInfo->clientId,  pNodeInfo->serverId, \
            pNodeInfo->seckeyid, optime, 0, tmpseckey2);

    //执行非 select 语句
    ret = IC_DBApi_ExecNSelSql(dbhdl, mysql);
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret, "func IC_DBApi_ExecNSelSql() err \n sql===>%s\n", mysql);
        goto END;
    }
END:

    return ret;

}


int KeyMngsvr_DBOp_UpdateSecKey(void *dbhdl, NodeSHMInfo *pNodeInfo) 
{
    int ret=0;
    char Mysql[1024]={0};
    sprintf(Mysql,"update SECMNG.seckyeinfo set state=1 where keyid=%d",pNodeInfo->seckeyid);

    if(dbhdl==NULL||pNodeInfo==NULL)
    {
        KeyMng_Log(__FILE__,__LINE__,KeyMngLevel[4],4,"KeyMngsvr_DBOp_UpdateSecKey error");
        ret=1;
        return ret;
    }
    else
    {
        KeyMng_Log(__FILE__,__LINE__,KeyMngLevel[2],2,"KeyMngsvr_DBOp_UpdateSecKey success");
    }
    //执行非 select 语句
    ret = IC_DBApi_ExecNSelSql(dbhdl, Mysql);
    if (ret != 0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret, "func IC_DBApi_ExecNSelSql() err \n sql===>%s\n", Mysql);
    }
    else
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"success");
    }

    return ret;

}
