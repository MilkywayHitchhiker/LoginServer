#include"stdafx.h"
#include<string>
#include"Parser.h"

bool Parser::LoadFile (char *name)
{
	FILE *fp;
	WCHAR *pWBuffer;
	fopen_s (&fp,name,"rb");
	if ( fp == NULL )
	{
		return false;
	}

	fseek (fp,0,SEEK_END);
	Size = ftell (fp);
	rewind (fp);
	pWBuffer = new WCHAR[Size];
	pBuffer = new char[Size];
	
	fread_s (pWBuffer,Size,Size,1,fp);

	fclose (fp);
	WideCharToMultiByte (CP_ACP, 0, pWBuffer, -1, pBuffer, Size, 0, 0);
	
	delete[]pWBuffer;

	return true;

}

bool Parser::SetArea (char *name)
{
	char *Position = pBuffer;
	int Length;
	char Word[256];
	int Start = 0;
	int End = 0;
	int flag = 0;
	
	AreaStart = 0;
	AreaEnd = Size;


	while ( 1 )
	{
		// ':'을 검색
		if ( Position[0] == ':' )
		{
			Position++;
			Start++;
			Length = 0;
			// ':' 뒤에 오는 글자를 검색해서 입력된 글자와 맞는지 확인.
			if ( GetNextWord (&Position, &Length) )
			{
				memset (Word,0,sizeof(Word));
				memcpy_s (Word,sizeof(Word),Position,Length);
				Start += Length;

				if ( 0 == strcmp (Word, name) )
				{
					// 맞다면 다시 반복문을 돌면서 '{' 중괄호 검색.
					while ( 1 )
					{
						//중괄호 여는곳을 찾았다면 중괄호 닫는곳을 검색.
						if ( Position[0] == '{' )
						{
							End = Start;
							while ( 1 )
							{
								//중괄호 닫는곳을 찾았다면 그대로 저장하고 종료.
								if ( Position[0] == '}' )
								{
									AreaStart = Start;
									AreaEnd = End;
									return true;
								}
								
								if ( flag > Size )
								{
									return false;
								}

								
								Position++;
								End++;
								flag++;

								
							}
						}

						if ( flag > Size )
						{
							return false;
						}

						Position++;
						Start++;
						flag++;
					}
				}
			}
		}

		if ( flag > Size )
		{
			return false;
		}


		Position++;
		Start++;
		flag++;
	}


}


bool  Parser::SkipNoneCommand (char **p)
{
	char *Buffer = *p;
	int cnt;

	for(cnt = 0 ; cnt < (AreaEnd - AreaStart) ; cnt++ )
	{
		//스페이스,엔터,탭 처리
		if ( Buffer[0] == ' ' || Buffer[0] == 0x0a || Buffer[0] == 0x0d || Buffer[0] == '\t' || Buffer[0] == ',' || Buffer[0] == 0x20 || Buffer[0] == 0x08 || Buffer[0] == '\"' )
		{
			Buffer++;
		}

		//한줄 주석 처리
		else if ( Buffer[0] == '/' && Buffer[1] == '/' )
		{
			for ( ; cnt < (AreaEnd - AreaStart); cnt++ )
			{
				if ( Buffer[0] == 0x0d && Buffer[1] == 0x0a )
				{
					Buffer++;
					Buffer++;
					break;
				}
				Buffer++;
			}
		}

		//다단 주석 건너 뛰기
		else if ( Buffer[0] == '/' && Buffer[1] == '*' )
		{
			for ( ; cnt < (AreaEnd - AreaStart); cnt++ )
			{
				if ( Buffer[0] == '*' && Buffer[1] == '/' )
				{
					Buffer++;
					Buffer++;
					break;
				}
				Buffer++;
			}
		}

		//위의 공백,탭,엔터,주석처리중 하나도 맞지 않으면 데이터로 판단.
		else
		{
			*p = Buffer;
			return true;
		}
	}
	//범위를 벗어나게 됨.
	return false;
}

bool  Parser::GetNextWord (char **Buffer, int *Length)
{
	char *p=*Buffer;
	int Len=0;
	int cnt;
	p = p + *Length;

	//파일의 크기를 넘어설경우
	if ( !SkipNoneCommand (&p) )
	{
		return false;
	}
	*Buffer = p;

	for ( cnt = 0 ; cnt < (AreaEnd - AreaStart); cnt++ )
	{


		//스페이스,엔터,탭 처리
		if ( p[0] == ' ' || p[0] == 0x0a || p[0] == 0x0d || p[0] == '\t' || p[0] == ',' || p[0] == 0x20 || p[0] == 0x08 || p[0] == ':' || p[0] == '{' || p[0] == '}' || p[0] == '\"' )
		{
			*Length = Len;
			return true;
		}

		p++;
		Len++;


	}
	return false;
}

bool  Parser::GetValue (char *name, int *p)
{
	char *Position = &pBuffer[AreaStart];
	char chWord[256];
	int Length = 0;

	//무한반복을 돌면서 단어검색.
	while ( GetNextWord(&Position,&Length) )
	{
		//Word버퍼에 찾은 단어를 저장
		memset (chWord,0,256);
		memcpy_s (chWord,sizeof(chWord),Position,Length);

		//찾은 단어가 입력한 단어와 같은지 검사.
		if ( 0 == strcmp (chWord, name) )
		{
			//맞다면 뒤에올 = 을 찾는다.
			if ( GetNextWord (&Position, &Length) )
			{
				memset (chWord, 0, 256);
				memcpy_s (chWord, sizeof (chWord), Position, Length);

				if ( 0 == strcmp (chWord, "=") )
				{
					if ( GetNextWord (&Position, &Length) )
					{
						memset (chWord, 0, 256);
						memcpy_s (chWord, sizeof (chWord), Position, Length);
						*p = atoi (chWord);
						return true;
					}

					return false;
				}
			}
			return false;
		}

	}
	return false;
}
bool  Parser::GetValue (char *name, char *p,int *MaxLength)
{
	char *Position = &pBuffer[AreaStart];
	char chWord[256];
	int Length = 0;

	//무한반복을 돌면서 단어검색.
	while ( GetNextWord (&Position, &Length) )
	{
		//Word버퍼에 찾은 단어를 저장
		memset (chWord, 0, 256);
		memcpy_s (chWord, sizeof (chWord), Position, Length);

		//찾은 단어가 입력한 단어와 같은지 검사.
		if ( 0 == strcmp (chWord, name) )
		{
			//맞다면 뒤에올 = 을 찾는다.
			if ( GetNextWord (&Position, &Length) )
			{
				memset (chWord, 0, 256);
				memcpy_s (chWord, sizeof (chWord), Position, Length);

				if ( 0 == strcmp (chWord, "=") )
				{
					if ( GetNextWord (&Position, &Length) )
					{
						memset (chWord, 0, 256);
						memcpy_s (chWord, sizeof (chWord), Position, Length);

						//인자로 받은 최대 길이 만큼 memcpy로 Word를 넘겨 준다.
						memcpy_s (p,*MaxLength,chWord,Length);
						*MaxLength = Length;
						return true;
					}

					return false;
				}
			}
			return false;
		}

	}
	return false;
	return true;
}
bool  Parser::GetValue (char *name, float *p)
{

	return true;
}
bool  Parser::GetValue (char *name, double *p)
{
	char *Position = &pBuffer[AreaStart];
	char chWord[256];
	int Length = 0;

	//무한반복을 돌면서 단어검색.
	while ( GetNextWord (&Position, &Length) )
	{
		//Word버퍼에 찾은 단어를 저장
		memset (chWord, 0, 256);
		memcpy_s (chWord, sizeof (chWord), Position, Length);

		//찾은 단어가 입력한 단어와 같은지 검사.
		if ( 0 == strcmp (chWord, name) )
		{
			//맞다면 뒤에올 = 을 찾는다.
			if ( GetNextWord (&Position, &Length) )
			{
				memset (chWord, 0, 256);
				memcpy_s (chWord, sizeof (chWord), Position, Length);

				if ( 0 == strcmp (chWord, "=") )
				{
					if ( GetNextWord (&Position, &Length) )
					{
						memset (chWord, 0, 256);
						memcpy_s (chWord, sizeof (chWord), Position, Length);
						*p = atof (chWord);
						return true;
					}

					return false;
				}
			}
			return false;
		}

	}
	return false;
	return true;
}