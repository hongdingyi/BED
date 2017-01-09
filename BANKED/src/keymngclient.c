#include "keymngclientop.h"
#include "keymng_msg.h"
#include <stdio.h>
#include <stdlib.h>
int Get_Command()
{
    int cmdtype=0;
    printf("**************************\n");   
    printf("      密钥管理系统        \n");	
    printf("**************************\n");  
    printf("      1--密码协商---      \n");
    printf("      2--密钥校验---      \n");
    printf("      3--密钥注销---      \n");
    printf("      4--密钥查看---      \n");
    printf("      0--退出系统---      \n");
    printf("**************************\n");  
    printf("**************************\n");  
    printf("cmd:");
    scanf("%d",&cmdtype);
    while(getchar()!='\n');
    return cmdtype;
}
int main()
{

    int    cmdtype;
    int    ret;
    MngClient_Info info;
    ret=MngClient_InitInfo(&info);
    if(ret!=0)
    {
        printf("初始化客户端失败，结束程序\n");
        return ret;
    }
    while(1)
    {
        system("clear");
        cmdtype=Get_Command();
        switch(cmdtype)
        {
                 //进行密钥协商
            case KeyMng_NEWorUPDATE:                
                ret=MngClient_Agree(&info);
                break;

                //进行密钥校验
            case KeyMng_Check:                
                ret=MngClient_Check(&info);
                break;
                
                //进行密钥注销
            case KeyMng_Revoke:                
                ret= MngClient_Revoke(&info);
                break;
                
                //进行密钥查看
            case KeyMng_View:                
                ret= MngClient_View(&info);
                break;
                
            case KeyMng_Exit:
                printf("已退出系统\n");
                exit(0);

            default:
                {
                    printf("输入的命令不支持\n");
                    ret=1;
                }
                break;
        }

        if(ret!=0)
        {
            printf("!!!!!!!!!!!!ERROR!!!!!!!!!!!!\n");
            printf("错误码:%x",ret);
        }

        else
        {
            printf("!!!!!!!!!!!SUCCESS!!!!!!!!!!\n");
        }
        getchar();      		

    }
    return 0;
}
