#ifndef __PSW_INTERFACE_EVT__
#define __PSW_INTERFACE_EVT__
/*
    ����:   Interface ����
    �ۼ���: �ڼ���(adsloader@naver.com)
    �ۼ���: 2012.05.25
    ���� :  Event Interface
*/

class NotificationInterface
{
public:
   
    // callback ����
    virtual void OnCreate() = 0;    
	virtual void OnDelete() = 0;     

};
 

#endif