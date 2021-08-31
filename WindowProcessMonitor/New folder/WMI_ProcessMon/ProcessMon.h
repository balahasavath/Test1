#pragma once
/*
    ����:   WMI�� �̿��� Process ����
    �ۼ���: �ڼ���(adsloader@naver.com)
    �ۼ���: 2012.05.25
    ���� :  MSDN�� WMI ���� Ȱ��
	���� :  MSDN�� ������ class�� ���ϰ� ���Ļ����
*/

#include "eventsink.h"
#include "EventInterface.h"

class CProcessMon : public NotificationInterface
{
protected:
	char m_szProcessName[1024];

public:
	CProcessMon(void);
	virtual ~CProcessMon(void);

	int StartWatching(char* szName);
	int StopWatching();

	virtual void OnCreate() = 0;    
	virtual void OnDelete() = 0;    

private:
	HRESULT hres;
	IWbemLocator *pLoc;
	IWbemServices *pSvc;
	IUnsecuredApartment* pUnsecApp;
	
	EventSink* pSink;
	EventSink* pSink2;

	IUnknown* pStubUnk;
	IWbemObjectSink* pStubSink;
};
