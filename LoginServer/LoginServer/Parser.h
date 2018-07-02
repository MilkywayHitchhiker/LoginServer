#include"stdafx.h"
#include<Windows.h>
class Parser
{
private:
	char *pBuffer;
	int Size;
	int AreaStart;
	int AreaEnd;

	bool SkipNoneCommand (char **Buffer);
	bool GetNextWord (char **Buffer, int *Length);

public:
	Parser (void)
	{

	}
	~Parser (void)
	{
		delete[]pBuffer;
	}
	bool LoadFile (char *name);

	bool SetArea (char *name);


	bool GetValue (char *name, int *p);
	bool GetValue (char *name, char *p,  int *Val);
	bool GetValue (char *name, float *p);
	bool GetValue (char *name, double *p);
};