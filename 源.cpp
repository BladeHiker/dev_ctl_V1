#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <malloc.h>
#include <Windows.h>
#include <cstring>
#include <memory.h>
#include <cmath>
#include <cctype>
#include <conio.h>
//***************MD5�㷨***************//
typedef struct
{
	unsigned int count[2];
	unsigned int state[4];
	unsigned char buffer[64];
} MD5_CTX;
#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))
#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))
#define FF(a, b, c, d, x, s, ac)  \
	{                             \
		a += F(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}
#define GG(a, b, c, d, x, s, ac)  \
	{                             \
		a += G(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}
#define HH(a, b, c, d, x, s, ac)  \
	{                             \
		a += H(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}
#define II(a, b, c, d, x, s, ac)  \
	{                             \
		a += I(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}
unsigned char PADDING[] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
void MD5Init(MD5_CTX *context)
{
	context->count[0] = 0;
	context->count[1] = 0;
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
}
void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (j < len)
	{
		output[j] = input[i] & 0xFF;
		output[j + 1] = (input[i] >> 8) & 0xFF;
		output[j + 2] = (input[i] >> 16) & 0xFF;
		output[j + 3] = (input[i] >> 24) & 0xFF;
		i++;
		j += 4;
	}
}
void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (j < len)
	{
		output[i] = (input[j]) |
					(input[j + 1] << 8) |
					(input[j + 2] << 16) |
					(input[j + 3] << 24);
		i++;
		j += 4;
	}
}
void MD5Transform(unsigned int state[4], unsigned char block[64])
{
	unsigned int a = state[0];
	unsigned int b = state[1];
	unsigned int c = state[2];
	unsigned int d = state[3];
	unsigned int x[64];
	MD5Decode(x, block, 64);
	FF(a, b, c, d, x[0], 7, 0xd76aa478);   /* 1 */
	FF(d, a, b, c, x[1], 12, 0xe8c7b756);  /* 2 */
	FF(c, d, a, b, x[2], 17, 0x242070db);  /* 3 */
	FF(b, c, d, a, x[3], 22, 0xc1bdceee);  /* 4 */
	FF(a, b, c, d, x[4], 7, 0xf57c0faf);   /* 5 */
	FF(d, a, b, c, x[5], 12, 0x4787c62a);  /* 6 */
	FF(c, d, a, b, x[6], 17, 0xa8304613);  /* 7 */
	FF(b, c, d, a, x[7], 22, 0xfd469501);  /* 8 */
	FF(a, b, c, d, x[8], 7, 0x698098d8);   /* 9 */
	FF(d, a, b, c, x[9], 12, 0x8b44f7af);  /* 10 */
	FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], 7, 0x6b901122);  /* 13 */
	FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], 5, 0xf61e2562);   /* 17 */
	GG(d, a, b, c, x[6], 9, 0xc040b340);   /* 18 */
	GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);  /* 20 */
	GG(a, b, c, d, x[5], 5, 0xd62f105d);   /* 21 */
	GG(d, a, b, c, x[10], 9, 0x2441453);   /* 22 */
	GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);  /* 24 */
	GG(a, b, c, d, x[9], 5, 0x21e1cde6);   /* 25 */
	GG(d, a, b, c, x[14], 9, 0xc33707d6);  /* 26 */
	GG(c, d, a, b, x[3], 14, 0xf4d50d87);  /* 27 */
	GG(b, c, d, a, x[8], 20, 0x455a14ed);  /* 28 */
	GG(a, b, c, d, x[13], 5, 0xa9e3e905);  /* 29 */
	GG(d, a, b, c, x[2], 9, 0xfcefa3f8);   /* 30 */
	GG(c, d, a, b, x[7], 14, 0x676f02d9);  /* 31 */
	GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], 4, 0xfffa3942);   /* 33 */
	HH(d, a, b, c, x[8], 11, 0x8771f681);  /* 34 */
	HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], 4, 0xa4beea44);   /* 37 */
	HH(d, a, b, c, x[4], 11, 0x4bdecfa9);  /* 38 */
	HH(c, d, a, b, x[7], 16, 0xf6bb4b60);  /* 39 */
	HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], 4, 0x289b7ec6);  /* 41 */
	HH(d, a, b, c, x[0], 11, 0xeaa127fa);  /* 42 */
	HH(c, d, a, b, x[3], 16, 0xd4ef3085);  /* 43 */
	HH(b, c, d, a, x[6], 23, 0x4881d05);   /* 44 */
	HH(a, b, c, d, x[9], 4, 0xd9d4d039);   /* 45 */
	HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], 23, 0xc4ac5665);  /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], 6, 0xf4292244);   /* 49 */
	II(d, a, b, c, x[7], 10, 0x432aff97);  /* 50 */
	II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], 21, 0xfc93a039);  /* 52 */
	II(a, b, c, d, x[12], 6, 0x655b59c3);  /* 53 */
	II(d, a, b, c, x[3], 10, 0x8f0ccc92);  /* 54 */
	II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], 21, 0x85845dd1);  /* 56 */
	II(a, b, c, d, x[8], 6, 0x6fa87e4f);   /* 57 */
	II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], 15, 0xa3014314);  /* 59 */
	II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], 6, 0xf7537e82);   /* 61 */
	II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], 15, 0x2ad7d2bb);  /* 63 */
	II(b, c, d, a, x[9], 21, 0xeb86d391);  /* 64 */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
	unsigned int i = 0, index = 0, partlen = 0;
	index = (context->count[0] >> 3) & 0x3F;
	partlen = 64 - index;
	context->count[0] += inputlen << 3;
	if (context->count[0] < (inputlen << 3))
		context->count[1]++;
	context->count[1] += inputlen >> 29;

	if (inputlen >= partlen)
	{
		memcpy(&context->buffer[index], input, partlen);
		MD5Transform(context->state, context->buffer);
		for (i = partlen; i + 64 <= inputlen; i += 64)
			MD5Transform(context->state, &input[i]);
		index = 0;
	}
	else
	{
		i = 0;
	}
	memcpy(&context->buffer[index], &input[i], inputlen - i);
}
void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
	unsigned int index = 0, padlen = 0;
	unsigned char bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56) ? (56 - index) : (120 - index);
	MD5Encode(bits, context->count, 8);
	MD5Update(context, PADDING, padlen);
	MD5Update(context, bits, 8);
	MD5Encode(digest, context->state, 16);
}
void MD5(unsigned char *encrypt, unsigned char *decrypt)
{
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, encrypt, strlen((char *)encrypt));
	MD5Final(&md5, decrypt);
}
//***************MD5�㷨***************//
enum LEVEL
{
	USER = 1,
	ADMIN,
	MASTER
};
struct Device
{
	char type[500]; //�ͺ�
	char name[500]; //����
	double price;   //�۸�
	long long deviceID;
	time_t timein;
	int state;
	bool fg_info;
	char info[10000];
	struct Device *dlink;
	struct Use *uRoot;
};
struct User
{
	char userID[50];
	char name[100];
	int level;
	unsigned char passwd[16];
	int usenum;
	struct Use *uselst[1000];
	struct User *next;
};
struct Use
{
	struct User *user;
	time_t useBeg;
	bool end;
	time_t useEnd;
	struct Use *link;
	struct Device *DevUse;
};
char *ctime_d(time_t *t)//time_tת��Ϊ�������е��ַ���
{
	char str[100];
	strcpy(str, ctime(t));
	static char strr[100];
	for (int i = 0; i < strlen(str) - 1; ++i)
	{
		strr[i] = str[i];
		strr[i + 1] = '\0';
	}
	return strr;
}
bool md5_eq(unsigned char *md51, unsigned char *md52)//MD5����ȶ�
{
	for (int i = 0; i < 16; ++i)
	{
		if (md51[i] != md52[i])
			return false;
	}
	return true;
}
time_t str2time_t(char str[50])//ʱ���ַ���תtime_t
{
	time_t tt;
	struct tm ttm;
	char m[5];
	//һ��Jan������Feb������Mar������Apr������May������June������July������Aug������Sept��ʮ��Oct��ʮһ��Nov��ʮ����Dec��
	char mm[12][5] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	sscanf(str, "%*s %s %d %d:%d:%d %d", m, &ttm.tm_mday, &ttm.tm_hour, &ttm.tm_min, &ttm.tm_sec, &ttm.tm_year);
	ttm.tm_year -= 1900;
	for (int i = 0; i < 12; ++i)
	{
		if (strcmp(m, mm[i]) == 0)
		{
			ttm.tm_mon = i;
			break;
		}
	}
	tt = mktime(&ttm);
	return tt;
}
void userLogin(struct User *userRoot, struct User **userLogin)//�û���¼
{
	bool verpass = 1;
	int errcnt = 0;
	while (1)
	{
		printf("UserID:");
		char loginID[50] = {0};
		scanf("%s", loginID);
		getchar();
		printf("Password:");
		unsigned char userPasswd[500] = {0};
		for (int i = 0; i < 500; ++i)
		{
			char c;
			c = getch();
			if (c == '\b')
			{
				--i;
				continue;
			}
			if (c != '\r')
			{
				userPasswd[i] = c;
				putchar('*');
			}
			else
				break;
		}
		unsigned char md5Passwd[16];
		MD5(userPasswd, md5Passwd);
		for (struct User *p = userRoot; p; p = p->next)
		{
			if (strcmp(p->userID, loginID) == 0 && md5_eq(p->passwd, md5Passwd))
			{
				system("cls");
				printf("\n��ӭ��%s\n", p->name);
				verpass = 0;
				*userLogin = p;
				return;
			}
		}
		if (verpass)
		{
			++errcnt;
			if (errcnt < 5)
			{
				printf("\n�û�ID���������������һ�Σ�\n");
				Sleep(1000);
			}
			else
			{
				system("color C0");
				printf("\n�û�ID�����������%ld���Ӻ�����!\n", (long)pow(2, (errcnt - 5)));
				Sleep(60 * 1000 * (long)pow(2, (errcnt - 5)));
				system("color 02");
			}
		}
	}
}
void User_Push_front_echo(struct User **UserRoot, char userID[], char name[], int level, unsigned char userpasswd[16])//����û�
{
	struct User *Userp = (struct User *)malloc(sizeof(struct User));
	Userp->next = *UserRoot;
	*UserRoot = Userp;
	strcpy(Userp->userID, userID);
	strcpy(Userp->name, name);
	Userp->level = level;
	Userp->usenum = -1;
	for (int i = 0; i < 16; ++i)
	{
		Userp->passwd[i] = userpasswd[i];
	}
}
void Dev_Push_front_echo(struct Device **DevRoot, char type[500], char name[500], double price, long long deviceID, time_t timein, int state, bool fg_info, char info[10000])//����豸
{
	struct Device *Devp = (struct Device *)malloc(sizeof(struct Device));
	Devp->dlink = *DevRoot;
	*DevRoot = Devp;
	strcpy(Devp->type, type);
	strcpy(Devp->name, name);
	Devp->price = price;
	Devp->deviceID = deviceID;
	Devp->uRoot = 0;
	Devp->fg_info = fg_info;
	if (Devp->fg_info)
		strcpy(Devp->info, info);
	Devp->timein = timein;
	Devp->state = true;
	return;
}
void Use_Push_front_echo(struct Device *DevRoot, struct User *UserRoot, long long DeviceID, char userID[50], char useBegs[100], int end, char useEnds[100])//������ü�¼
{
	struct Device *DevCho = 0;
	for (struct Device *p = DevRoot; p; p = p->dlink)
	{
		if (p->deviceID == DeviceID)
		{
			DevCho = p;
			break;
		}
	}
	struct User *UserCho = 0;
	for (struct User *p = UserRoot; p; p = p->next)
	{
		if (strcmp(p->userID, userID) == 0)
		{
			UserCho = p;
			break;
		}
	}
	if (DevCho && UserCho)
	{
		struct Use *up = (struct Use *)malloc(sizeof(struct Use));
		up->link = DevCho->uRoot;
		DevCho->uRoot = up;
		up->DevUse = DevCho;
		up->user = UserCho;
		up->end = end;
		DevCho->state = end ? DevCho->state : false;
		time(&up->useBeg);
		up->useBeg = str2time_t(useBegs);
		if (end)
		{
			up->useEnd = str2time_t(useEnds);
		}
		++UserCho->usenum;
		UserCho->uselst[UserCho->usenum] = up;
	}
	return;
}
void User_db_w(struct User *user)//�����ݿ�д�뵥���û���Ϣ
{
	FILE *db_user = fopen("db_user.txt", "a+");
	if (db_user)
	{
		fprintf(db_user, "%s %s %d ", user->userID, user->name, user->level);
		for (int i = 0; i < 16; ++i)
		{
			fprintf(db_user, "%02x", user->passwd[i]);
		}
		fprintf(db_user, "\n");
		fclose(db_user);
	}
	return;
}
void Device_db_w(struct Device *Dev)//�����ݿ�д�뵥���豸��Ϣ
{
	FILE *db_Dev = fopen("db_Device.txt", "a+");
	if (db_Dev)
	{
		fprintf(db_Dev, "%s %s %.2lf %lld %s %d %s\n", Dev->type, Dev->name, Dev->price, Dev->deviceID, ctime(&Dev->timein), Dev->fg_info, Dev->fg_info ? Dev->info : "null");
		fclose(db_Dev);
	}
	return;
}
void Use_db_w(struct Use *Use_Cho)//�����ݿ�д�뵥�����ü�¼
{
	FILE *db_Use = fopen("db_Use.txt", "a+");
	if (db_Use)
	{
		fprintf(db_Use, "%lld %s %s %d %s\n", Use_Cho->DevUse->deviceID, Use_Cho->user->userID, ctime(&Use_Cho->useBeg), Use_Cho->end, Use_Cho->end ? ctime(&Use_Cho->useEnd) : "null");
		fclose(db_Use);
	}
	return;
}
void User_Push_front(struct User **UserRoot, int level)//����û���
{
	struct User *Userp = (struct User *)malloc(sizeof(struct User));
	Userp->next = *UserRoot;
	*UserRoot = Userp;
	while (1)
	{
		bool fg_if_pass = true;
		printf("�������û�ID��");
		scanf("%s", Userp->userID);
		for (struct User *up = (*UserRoot)->next; up; up = up->next)
		{
			if (strcmp(up->userID, Userp->userID) == 0)
			{
				printf("�û�ID%s�ѱ�ռ�ã������ID����\n", Userp->userID);
				fg_if_pass = false;
			}
		}
		if (fg_if_pass)
			break;
	}
	printf("�����û�����");
	scanf("%s", Userp->name);
	getchar();
	Userp->level = level;
	Userp->usenum = -1;
	bool fg_passwd_ok = true;
	unsigned char userPasswd1[500] = {0}, userPasswd2[500] = {0};
	int passwdlen1 = 0, passwdlen2 = 0;
	while (fg_passwd_ok)
	{
		printf("���������룺");
		passwdlen1 = 0, passwdlen2 = 0;
		for (int i = 0; i < 500; ++i)
		{
			userPasswd1[i] = 0;
			userPasswd2[i] = 0;
		}
		for (int i = 0; i < 500; ++i)
		{
			char c;
			c = getch();
			if (c == '\b')
			{
				--i;
				continue;
			}
			if (c != '\r')
			{
				userPasswd1[i] = c;
				putchar('*');
				++passwdlen1;
			}
			else
				break;
		}
		int err_cnt = 0;
		while (1)
		{
			printf("\n�ظ��������룺");
			passwdlen2 = 0;
			for (int i = 0; i < 500; ++i)
				userPasswd2[i] = 0;
			for (int i = 0; i < 500; ++i)
			{
				char c;
				c = getch();
				if (c == '\b')
				{
					--i;
					continue;
				}
				if (c != '\r')
				{
					userPasswd2[i] = c;
					putchar('*');
					++passwdlen2;
				}
				else
					break;
			}
			if (passwdlen1 == passwdlen2)
			{
				bool iseql = true;
				for (int i = 0; i < passwdlen1; ++i)
				{
					if (userPasswd1[i] != userPasswd2[i])
					{
						iseql = false;
						break;
					}
				}
				if (iseql)
				{
					fg_passwd_ok = false;
					break;
				}
			}
			else
			{
				++err_cnt;
				if (err_cnt < 5)
					printf("������һ�Σ�\n");
				else
				{
					printf("�����ԣ�\n");
					break;
				}
			}
		}
	}
	unsigned char md5Passwd[16];
	MD5(userPasswd1, md5Passwd);
	for (int i = 0; i < 16; ++i)
	{
		Userp->passwd[i] = md5Passwd[i];
	}
	User_db_w(Userp);
}
void dbRead(struct User **UserRoot, struct Device **DevRoot)//��ȡ���ݿ�
{
	system("cls");
	printf("��ȡ���ݿ���");
	FILE *db_user = fopen("db_user.txt", "r");
	FILE *db_device = fopen("db_device.txt", "r");
	FILE *db_use = fopen("db_use.txt", "r");
	char userID[50], name[100];
	int level;
	unsigned char userpasswd[50];
	if (db_user)
	{
		printf("\n-�������û����ݿ�");
		while (~fscanf(db_user, "%s %s %d ", userID, name, &level))
		{
			for (int i = 0; i < 16; ++i)
				fscanf(db_user, "%02x", &userpasswd[i]);
			fscanf(db_user, "\n");
			User_Push_front_echo(UserRoot, userID, name, level, userpasswd);
			printf("��");
		}
		fclose(db_user);
		printf("\n�û����ݿ��ȡ��ɣ�\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("\n�û����ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("\n�û����ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	if (db_device)
	{
		printf("\n-�������豸���ݿ�");
		char type[500];
		char name[500];
		double price;
		long long deviceID;
		time_t timein;
		int fg_info;
		char info[10000];
		struct tm tt;
		char ttt[50];
		while (~fscanf(db_device, "%s %s %lf %lld", type, name, &price, &deviceID))
		{
			if (strlen(type) == 0)
				break;
			fgets(ttt, 50, db_device);
			fscanf(db_device, "%d %s\n", &fg_info, info);
			timein = str2time_t(ttt);
			Dev_Push_front_echo(DevRoot, type, name, price, deviceID, timein, 1, fg_info, info);
			printf("��");
		}
		fclose(db_device);
		printf("\n�豸���ݿ��ȡ��ɣ�\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("�豸���ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("�豸���ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	if (db_use)
	{
		printf("\n-�������������ݿ�");
		long long DeviceID;
		char userID[50];
		char useBegs[100];
		int end;
		char useEnds[100];
		while (~fscanf(db_use, "%lld %s ", &DeviceID, userID, useBegs, &end, useEnds))
		{
			fgets(useBegs, 100, db_use);
			fscanf(db_use, "%d ", &end);
			fgets(useEnds, 100, db_use);
			Use_Push_front_echo(*DevRoot, *UserRoot, DeviceID, userID, useBegs, end, useEnds);
			printf("��");
		}
		fclose(db_use);
		printf("\n�������ݿ��ȡ��ɣ�\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("\n�������ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("\n�������ݿ��ȡʧ�ܣ�\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	system("cls");
	return;
}
bool YN_qus_0(bool deft)//�ж�����Y/N
{
	char in_qus[1000];
	char c;
	int i = 0;
	do
	{
		c = getchar();
		in_qus[i++] = c;
	} while (c != '\n');
	if (strlen(in_qus) == 1)
	{
		if (toupper(in_qus[0]) == 'Y')
			return true;
		else if (toupper(in_qus[0] == 'N'))
			return false;
	}
	return deft;
}
bool YN_qus_1()//�ж�����Y/N
{
	char in[200] = {0};
	while (scanf("%s", in))
	{
		if (strlen(in) == 1)
		{
			if (toupper(in[0]) == 'Y')
				return true;
			else if (toupper(in[0]) == 'N')
				return false;
		}
	}
}
void Dev_push_front(struct Device **DevRoot)//����豸��
{
	struct Device *Devp = (struct Device *)malloc(sizeof(struct Device));
	Devp->dlink = *DevRoot;
	*DevRoot = Devp;
	printf("¼�����豸\n");
	printf("�������豸�ͺţ�");
	scanf("%s", Devp->type);
	printf("�������豸���ƣ�");
	scanf("%s", Devp->name);
	printf("�������豸�۸񣺣�");
	scanf("%lf", &Devp->price);
	while (1)
	{
		bool fg_id_pass = true;
		printf("�������豸ID(���а��������ֹ���)��");
		scanf("%lld", &Devp->deviceID);
		for (struct Device *dp = (*DevRoot)->dlink; dp; dp = dp->dlink)
		{
			if (dp->deviceID == Devp->deviceID)
			{
				printf("�豸ID%lld�ѱ�ռ�ã������ID���ԣ�\n", Devp->deviceID);
				fg_id_pass = false;
			}
		}
		if (fg_id_pass)
			break;
	}

	Devp->uRoot = 0;
	printf("�Ƿ����뱸ע��(Y/N)��");
	Devp->fg_info = YN_qus_1();
	if (Devp->fg_info)
	{
		printf("�����뱸ע��Ϣ��\n");
		scanf("%s", Devp->info);
	}
	time(&Devp->timein);
	Devp->state = true;
	system("cls");
	printf("�豸¼��ɹ���%s\n", ctime_d(&Devp->timein));
	printf("�ͺţ�%s\t���ƣ�%s\t�۸񣺣�%.2lf\t�豸ID��%lld\t��ע��%s\n", Devp->type, Devp->name, Devp->price, Devp->deviceID, Devp->fg_info ? Devp->info : "�ޱ�ע");
}
struct Device *Dev_find(struct Device *DevRoot)//�豸����ģ��
{
	printf("�豸����\n");
	printf("0.�����ϼ��˵�\n");
	printf("1.ͨ���豸ID����\n");
	printf("2.ͨ���豸�ͺż���\n");
	printf("3.ͨ���豸���Ƽ���\n");
	printf("��ѡ�������ʽ(0,1,2,3)��");
	int menu_choose;
	while (1)
	{
		scanf("%d", &menu_choose);
		if (menu_choose == 0 || menu_choose == 1 || menu_choose == 2 || menu_choose == 3)
			break;
	}
	if (menu_choose == 0)
	{
		return 0;
	}
	else if (menu_choose == 1)
	{
		printf("������Ϸ��豸ID��");
		long long ID_find;
		scanf("%lld", &ID_find);
		for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
		{
			if (dp->deviceID == ID_find)
			{
				printf("��ѯ���豸��\n");
				printf("�ͺţ�%s\t���ƣ�%s\t�۸񣺣�%.2lf\t�豸ID��%lld\t¼��ʱ�䣺%s\t��ע��%s\n", dp->type, dp->name, dp->price, dp->deviceID, ctime_d(&dp->timein), dp->fg_info ? dp->info : "�ޱ�ע");
				return dp;
			}
		}
		printf("�Ҳ���ID%lld���豸����˶Ժ����ԣ�\n", ID_find);
		//system("pause");
		return 0;
	}
	else if (menu_choose == 2)
	{
		printf("������Ҫ��ѯ���豸�ͺŹؼ��֣�");
		char dev_find_word[500];
		scanf("%s", dev_find_word);
		int find_cnt = 0;
		struct Device *dFind[200] = {NULL};
		for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
		{
			if (strstr(dp->type, dev_find_word))
			{
				if (!find_cnt)
				{
					printf("�ҵ������豸��\n");
					printf("#���\t�豸ID\t�ͺ�\t����\t�۸�\t¼��ʱ��\t\t\t��ע\n");
				}
				++find_cnt;
				dFind[find_cnt] = dp;
				printf("#%d.\t%lld\t%s\t%s\t%.2lf\t%s\t%s\n", find_cnt, dp->deviceID, dp->type, dp->name, dp->price, ctime_d(&dp->timein), dp->fg_info ? dp->info : "�ޱ�ע");
			}
		}
		if (!find_cnt)
		{
			printf("�Ҳ����ͺ��а����˹ؼ��ֵ��豸��������һ�Σ�\n");
			system("pause");
			return 0;
		}
		else
		{
			printf("�ҵ�%d���豸��Ϣ!", find_cnt);
			if (find_cnt == 1)
			{
				return dFind[find_cnt];
			}
			else
			{
				printf("�����������¼��Ӧ���(1~%d)", find_cnt);
				int choose_find;
				while (1)
				{
					scanf("%d", &choose_find);
					if (choose_find > 0 && choose_find <= find_cnt)
						break;
				}
				return dFind[choose_find];
			}
		}
	}
	else if (menu_choose == 3)
	{
		printf("������Ҫ��ѯ���豸���ƹؼ��֣�");
		char dev_find_word[500];
		scanf("%s", dev_find_word);
		int find_cnt = 0;
		struct Device *dFind[200] = {NULL};
		for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
		{
			if (strstr(dp->name, dev_find_word))
			{
				if (!find_cnt)
				{
					printf("�ҵ������豸��\n");
					printf("#���\t�豸ID\t�ͺ�\t����\t�۸�\t¼��ʱ��\t\t��ע\n");
				}
				++find_cnt;
				dFind[find_cnt] = dp;
				printf("#%d.\t%lld\t%s\t%s\t%.2lf\t%s\t%s\n", find_cnt, dp->deviceID, dp->type, dp->name, dp->price, ctime_d(&dp->timein), dp->fg_info ? dp->info : "�ޱ�ע");
			}
		}
		if (!find_cnt)
		{
			printf("�Ҳ����ͺ��а����˹ؼ��ֵ��豸��������һ�Σ�\n");
			system("pause");
			return 0;
		}
		else
		{
			printf("�ҵ�%d���豸��Ϣ!", find_cnt);
			if (find_cnt == 1)
			{
				return dFind[find_cnt];
			}
			else
			{
				printf("�����������¼��Ӧ���(1~%d)", find_cnt);
				int choose_find;
				while (1)
				{
					scanf("%d", &choose_find);
					if (choose_find > 0 && choose_find <= find_cnt)
						break;
				}
				return dFind[choose_find];
			}
		}
	}
	return 0;
}
void Dev_edit(struct Device *DevCho)//�豸�༭ģ��
{
	while (1)
	{
		system("cls");
		printf("��ǰѡ���豸��");
		printf("�ͺţ�%s\t���ƣ�%s\t�۸񣺣�%.2lf\t�豸ID��%lld\t¼��ʱ�䣺%s\t��ע��%s\n", DevCho->type, DevCho->name, DevCho->price, DevCho->deviceID, ctime_d(&DevCho->timein), DevCho->fg_info ? DevCho->info : "�ޱ�ע");
		printf("0.�����޸�\n");
		printf("1.�޸��ͺ�\n");
		printf("2.�޸�����\n");
		printf("3.�޸ļ۸�\n");
		printf("4.�޸ı�ע\n");
		printf("������ѡ���޸���(0,1,2,3,4)��");
		int choose_menu;
		while (1)
		{
			scanf("%d", &choose_menu);
			if (choose_menu >= 0 && choose_menu < 5)
				break;
		}
		if (choose_menu == 0)
		{
			return;
		}
		else if (choose_menu == 1)
		{
			printf("Ҫ���ͺ��޸�Ϊ��");
			scanf("%s", DevCho->type);
		}
		else if (choose_menu == 2)
		{
			printf("Ҫ�������޸�Ϊ��");
			scanf("%s", DevCho->name);
		}
		else if (choose_menu == 3)
		{
			printf("Ҫ���۸��޸�Ϊ��");
			scanf("%lf", &DevCho->price);
		}
		else if (choose_menu == 4)
		{
			if (!DevCho->fg_info)
			{
				printf("�����±�ע��");
				DevCho->fg_info = true;
			}
			else
			{
				printf("Ҫ����ע�޸�Ϊ��");
			}
			scanf("%s", DevCho->info);
		}
		printf("�޸ĳɹ���\n");
		system("pause");
	}
}
void Dev_del(struct Device **DevRoot, struct Device *DevCho)//�豸ɾ������
{
	struct Device *dp = *DevRoot;
	if (*DevRoot != DevCho)
	{
		for (; dp->dlink; dp = dp->dlink)
		{
			if (dp->dlink == DevCho)
				break;
		}
		dp->dlink = DevCho->dlink;
		DevCho->dlink = 0;
		free(DevCho);
	}
	else
	{
		*DevRoot = (*DevRoot)->dlink;
		dp->dlink = 0;
		free(dp);
	}
	return;
}
void Use_Push_front(struct Device *DevRoot, struct User *UserLogin)//���ü�¼���
{
	printf("��ѡ��Ҫ���õ��豸��\n");
	struct Device *DevCho = 0;
	DevCho = Dev_find(DevRoot);
	if (!DevCho)
	{
		printf("δѡ���豸�������ԣ�\n");
		return;
	}
	if (DevCho->state)
	{
		printf("�����Ե�ǰ�û���%s���������\n", UserLogin->name);
		struct Use *up = (struct Use *)malloc(sizeof(struct Use));
		up->link = DevCho->uRoot;
		DevCho->uRoot = up;
		up->DevUse = DevCho;
		up->user = UserLogin;
		up->end = false;
		DevCho->state = false;
		time(&up->useBeg);
		++UserLogin->usenum;
		UserLogin->uselst[UserLogin->usenum] = up;
		printf("���óɹ������ÿ�ʼʱ�䣺%s", ctime_d(&up->useBeg));
		system("pause");
	}
	else
	{
		printf("�豸�ѱ����ã���ѡ�������豸��\n");
		system("pause");
	}
	return;
}
void Use_Back(struct Device *DevRoot, struct User *UserLogin)//�黹�豸
{
	printf("��ѡ��Ҫ�黹���豸��\n");
	struct Device *DevCho = 0;
	DevCho = Dev_find(DevRoot);
	if (!DevCho)
	{
		printf("δѡ���豸�������ԣ�\n");
		system("pause");
		return;
	}
	printf("���ڹ黹\n");
	struct Use *Up;
	for (struct Use *up = DevCho->uRoot; up; up = up->link)
	{
		printf(".");
		if (up->user == UserLogin)
		{
			time(&up->useEnd);
			up->end = true;
			DevCho->state = true;
			printf("\n�黹�ɹ����黹ʱ�䣺%s\n", ctime_d(&up->useEnd));
			system("pause");
			return;
		}
	}
	printf("�Ҳ����������ü�¼���黹ʧ�ܣ�\n");
	system("pause");
	return;
}
struct User *User_find(struct User *UserRoot)//�����û�
{
	printf("ѡ���û�\n");
	printf("0.�����ϼ��˵�\n");
	printf("1.ͨ���û�ID�����û�\n");
	printf("2.�г�ȫ���û�\n");
	printf("����������ѡ����(0,1,2)��");
	int Choose;
	while (1)
	{
		scanf("%d", &Choose);
		if (Choose == 1 || Choose == 2 || Choose == 0)
			break;
	}
	if (Choose == 0)
	{
		return 0;
	}
	else if (Choose == 1)
	{
		char User_ind[50];
		printf("�������û�ID:");
		scanf("%s", &User_ind);
		for (struct User *p = UserRoot; p; p = p->next)
		{
			if (strcmp(User_ind, p->userID) == 0)
			{
				printf("�������û�:\n");
				printf("[%s]%s(%s)\n", (p->level == 1) ? "��ͨ�û�" : (p->level == 2) ? "����Ա" : "��������Ա", p->name, p->userID);
				return p;
			}
		}
		printf("�Ҳ����û���\n");
		system("pause");
	}
	else
	{
		struct User *users[20] = {0};
		int cnt = 1;
		for (struct User *p = UserRoot; p; p = p->next)
		{
			printf("#%d.[%s]%s(%s)\n", cnt, (p->level == 1) ? "��ͨ�û�" : (p->level == 2) ? "����Ա" : "��������Ա", p->name, p->userID);
			users[cnt] = p;
			cnt++;
			if (cnt == 11 || !p->next)
			{
				if (!p->next)
				{
					printf("\n#������ȫ���û�#\n\n");
				}
				printf("�����û�ǰ���ѡ���û�������0��ҳ(0,%d~%d):", 1, cnt - 1);
				int t;
				while (1)
				{
					scanf("%d", &t);
					if (t >= 0 && t < cnt)
					{
						break;
					}
				}
				if (t == 0)
				{
					if (p->next)
					{
						continue;
					}
					else
					{
						printf("������ȫ���û���δѡ���û���������һ��\n");
						system("pause");
						return 0;
					}
				}
				else
				{
					printf("�������û�:\n");
					printf("[%s]%s(%s)\n", (users[t]->level == 1) ? "��ͨ�û�" : (users[t]->level == 2) ? "����Ա" : "��������Ա", users[t]->name, users[t]->userID);
					system("pause");
					return users[t];
				}
				cnt = 1;
			}
		}
	}
}
struct User *User_find_1(struct User *UserRoot)//������ͨ�û�
{
	printf("ѡ���û�\n");
	printf("0.�����ϼ��˵�\n");
	printf("1.ͨ���û�ID������ͨ�û�\n");
	printf("2.�г�ȫ����ͨ�û�\n");
	printf("����������ѡ����(0,1,2)��");
	int Choose;
	while (1)
	{
		scanf("%d", &Choose);
		if (Choose == 1 || Choose == 2 || Choose == 0)
			break;
	}
	if (Choose == 0)
	{
		return 0;
	}
	else if (Choose == 1)
	{
		char User_ind[50];
		printf("�������û�ID:");
		scanf("%s", &User_ind);
		for (struct User *p = UserRoot; p; p = p->next)
		{
			if (strcmp(User_ind, p->userID) == 0 && p->level == USER)
			{
				printf("�������û�:\n");
				printf("[%s]%s(%s)\n", (p->level == 1) ? "��ͨ�û�" : (p->level == 2) ? "����Ա" : "��������Ա", p->name, p->userID);
				return p;
			}
		}
	}
	else
	{
		struct User *users[20] = {0};
		int cnt = 1;
		for (struct User *p = UserRoot; p; p = p->next)
		{
			if (p->level == USER)
			{
				printf("#%d.[%s]%s(%s)\n", cnt, (p->level == 1) ? "��ͨ�û�" : (p->level == 2) ? "����Ա" : "��������Ա", p->name, p->userID);
				users[cnt] = p;
				cnt++;
			}
			if (cnt == 11 || !p->next)
			{
				if (!p->next)
				{
					printf("\n#������ȫ����ͨ�û�#\n\n");
				}
				printf("�����û�ǰ���ѡ���û�������0��ҳ(0,1~%d):", cnt - 1);
				int t;
				while (1)
				{
					scanf("%d", &t);
					if (t >= 0 && t < cnt)
					{
						break;
					}
				}
				if (t == 0)
				{
					if (p->next)
					{
						continue;
					}
					else
					{
						printf("������ȫ����ͨ�û���δѡ���û���������һ��\n");
						system("pause");
						return 0;
					}
				}
				else
				{
					printf("�������û�:\n");
					printf("[%s]%s(%s)\n", (users[t]->level == 1) ? "��ͨ�û�" : (users[t]->level == 2) ? "����Ա" : "��������Ա", users[t]->name, users[t]->userID);
					system("pause");
					return users[t];
				}
				cnt = 1;
			}
		}
	}
	printf("�Ҳ����û���\n");
	system("pause");
	return 0;
}
void Use_View(struct Device *DevRoot, struct User *UserRoot)//��ѯ���ü�¼
{
	printf("�豸���������ѯ\n");
	printf("0.�����ϼ��˵�\n");
	printf("1.��ѯ�û��������\n");
	printf("2.��ѯ�豸���������\n");
	printf("3.��ѯȫ���������\n");
	printf("��ѡ���ܱ��(1,2,3,0)��");
	int Choose_use;
	while (1)
	{
		scanf("%d", &Choose_use);
		if (Choose_use < 4 && Choose_use >= 0)
		{
			break;
		}
	}
	if (Choose_use == 0)
	{
		return;
	}
	else if (Choose_use == 1)
	{
		struct User *UserCho = User_find(UserRoot);
		if (UserCho)
		{
			if (UserCho->usenum == -1)
			{
				printf("�û�%s�������豸��¼\n", UserCho->name);
				system("pause");
				return;
			}
			else
			{
				printf("�������û�%s��ȫ�����ü�¼\n", UserCho->name);
				for (int i = 0; i <= UserCho->usenum; ++i)
				{
					printf("�豸���ƣ�%s\t�豸ID��%lld\t����ʱ�䣺%s\t", UserCho->uselst[i]->DevUse->name, UserCho->uselst[i]->DevUse->deviceID, ctime_d(&UserCho->uselst[i]->useBeg));
					if (UserCho->uselst[i]->end)
					{
						printf("�黹ʱ��%s\n", ctime_d(&UserCho->uselst[i]->useEnd));
					}
					else
					{
						printf("δ�黹�豸\n");
					}
				}
				system("pause");
				return;
			}
		}
	}
	else if (Choose_use == 2)
	{
		struct Device *DevCho = Dev_find(DevRoot);
		if (DevCho)
		{
			if (DevCho->uRoot)
			{
				for (struct Use *p = DevCho->uRoot; p; p = p->link)
				{
					printf("�����ˣ�[%s]%s(%s)\t", (p->user->level == 1) ? "��ͨ�û�" : (p->user->level == 2) ? "����Ա" : "��������Ա", p->user->name, p->user->userID);
					printf("����ʱ�䣺%s\t", ctime_d(&p->useBeg));
					if (p->end)
					{
						printf("�黹ʱ��%s\n", ctime_d(&p->useEnd));
					}
					else
					{
						printf("δ�黹�豸\n");
					}
				}
			}
			else
			{
				printf("���豸�������ü�¼\n");
				system("pause");
				return;
			}
		}
	}
	else if (Choose_use == 3)
	{
		bool fg_print = false;
		for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
		{
			for (struct Use *up = dp->uRoot; up; up = up->link)
			{
				fg_print = true;
				printf("�豸���ƣ�%s\t�豸ID%lld\t", up->DevUse->name, up->DevUse->deviceID);
				printf("�����ˣ�[%s]%s(%s)\t", (up->user->level == 1) ? "��ͨ�û�" : (up->user->level == 2) ? "����Ա" : "��������Ա", up->user->name, up->user->userID);
				printf("����ʱ�䣺%s\t", ctime_d(&up->useBeg));
				if (up->end)
				{
					printf("�黹ʱ�䣺%s\n", ctime_d(&up->useEnd));
				}
				else
				{
					printf("δ�黹�豸\n");
				}
			}
		}
		if (!fg_print)
		{
			printf("�����豸�������ü�¼\n");
		}
		system("pause");
		return;
	}
	system("pause");
	return;
}
void Device_rep_out(struct Device *DevRoot)//�豸����
{
	FILE *Device_rep = fopen("Device_report.txt", "w+");
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		fprintf(Device_rep, "�豸ID��%lld\t�豸���ƣ�%s\t�۸�%.2lf\t���ʱ�䣺%s\t�ڿ�״̬��%s\t��ע��%s\n", dp->deviceID, dp->name, dp->price, ctime_d(&dp->timein), dp->state ? "�ڿ�" : "���", dp->fg_info ? dp->info : "�ޱ�ע");
	}
	fclose(Device_rep);
	return;
}
void User_rep_out(struct User *UserRoot)//�û�����
{
	FILE *User_rep = fopen("User_report.txt", "w+");
	for (struct User *up = UserRoot; up; up = up->next)
	{
		fprintf(User_rep, "�û�ID��%s\t�û�����%s\t�û��飺%s\n", up->userID, up->name, (up->level == 1) ? "��ͨ�û�" : (up->level == 2) ? "����Ա" : "��������Ա");
	}
	fclose(User_rep);
	return;
}
void Use_rep_out(struct Device *DevRoot)//���ñ���
{
	FILE *Use_rep = fopen("Use_report.txt", "w+");
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		for (struct Use *up = dp->uRoot; up; up = up->link)
		{
			fprintf(Use_rep, "�豸���ƣ�%s\t�豸ID%lld\t", up->DevUse->name, up->DevUse->deviceID);
			fprintf(Use_rep, "�����ˣ�[%s]%s(%s)\t", (up->user->level == 1) ? "��ͨ�û�" : (up->user->level == 2) ? "����Ա" : "��������Ա", up->user->name, up->user->userID);
			fprintf(Use_rep, "����ʱ�䣺%s\t", ctime_d(&up->useBeg));
			if (up->end)
			{
				fprintf(Use_rep, "�黹ʱ�䣺%s\n", ctime_d(&up->useEnd));
			}
			else
			{
				fprintf(Use_rep, "δ�黹�豸\n");
			}
		}
	}
	fclose(Use_rep);
	return;
}
void User_pop(struct User **UserRoot, struct User *UserCho)//ɾ���û�
{
	struct User *upb = *UserRoot;
	if (*UserRoot != UserCho)
	{
		for (; upb->next != UserCho;)
		{
			upb = upb->next;
		}
		upb->next = UserCho->next;
		UserCho->next = 0;
		free(UserCho);
	}
	else
	{
		*UserRoot = UserCho->next;
		UserCho->next = 0;
		free(UserCho);
	}
	printf("��ɾ���û�\n");
	return;
}
void User_cha(struct User **UserRoot, struct User **UserLogin)//�û�Ȩ���޸�
{
	struct User *User_Cho = User_find(*UserRoot);
	if (User_Cho)
	{
		printf("0.�����ϼ��˵�\n");
		printf("1.�޸�ѡ���û�Ȩ��\n");
		printf("2.ɾ��ѡ���û�\n");
		printf("��������ѡ����(0,1,2)��");
		int menu_cho;
		while (1)
		{
			scanf("%d", &menu_cho);
			if (menu_cho >= 0 && menu_cho < 3)
			{
				break;
			}
		}
		if (menu_cho == 0)
		{
			return;
		}
		else if (menu_cho == 1)
		{
			printf("��ǰȨ��Ϊ[%s],��ѡ��Ҫ��ѡ�û�����Ȩ����(1.��ͨ�û�2.����Ա3.��������Ա)", (User_Cho->level == 1) ? "��ͨ�û�" : (User_Cho->level == 2) ? "����Ա" : "��������Ա");
			int menu_sub;
			while (1)
			{
				scanf("%d", &menu_sub);
				if (menu_cho > 0 && menu_cho < 4)
					break;
			}
			User_Cho->level = menu_sub;
			printf("%s���û�Ȩ�����޸�Ϊ[%s]\n", User_Cho->name, (User_Cho->level == 1) ? "��ͨ�û�" : (User_Cho->level == 2) ? "����Ա" : "��������Ա");
			system("pause");
			return;
		}
		else if (menu_cho == 2)
		{
			printf("�����Ҫɾ�����û���(Y/N)��\n");
			if (YN_qus_1())
			{
				if (User_Cho == *UserLogin)
				{
					printf("��¼�е��˻�����ɾ�������˳���¼�����ɾ��������\n");
					*UserLogin = 0;
				}
				User_pop(UserRoot, User_Cho);
			}
			else
			{
				printf("��ȡ������\n");
			}
			system("pause");
		}
	}
}
void User_f5_echo(struct User *UserRoot)//ˢ���û����ݿ�
{
	FILE *f = fopen("db_User.txt", "w+");
	fclose(f);
	for (struct User *up = UserRoot; up; up = up->next)
	{
		User_db_w(up);
	}
	return;
}
void Dev_f5_echo(struct Device *DevRoot)//ˢ���豸���ݿ�
{
	FILE *f = fopen("db_Device.txt", "w+");
	fclose(f);
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		Device_db_w(dp);
	}
	return;
}
void Use_f5_echo(struct Device *DevRoot)//ˢ�����ü�¼���ݿ�
{
	FILE *f = fopen("db_Use.txt", "w+");
	fclose(f);
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		for (struct Use *up = dp->uRoot; up; up = up->link)
		{
			Use_db_w(up);
		}
	}
	return;
}
void Free_d(struct Device* DevRoot, struct User* UserRoot)//free
{
	for (struct Device* dp = DevRoot; dp; dp = dp->dlink)
	{
		if (dp->uRoot)
			free(dp->uRoot);
	}
	if (DevRoot)
		free(DevRoot);
	if (UserRoot)
		free(UserRoot);
}
int main()
{
	system("color 0C");
	printf("�豸����ϵͳ V1 for Windows By.BladeHiker\n");
	for (int i = 0; i < 40; ++i)
	{
		printf(">");
		Sleep(121 - i * 3);
	}
	Sleep(500);
	system("cls");
	//��¼�û���ʾ
	struct User *UserLogin = 0;
	//�û���ָ��
	struct User *UserRoot = 0;
	//�豸��ָ��
	struct Device *DevRoot = 0;
	//���ݿ��ȡ
	dbRead(&UserRoot, &DevRoot);
	while (1)
	{
		system("color 02");
		//�ж��û����ݿ��Ƿ����
		if (UserRoot)
		{
			userLogin(UserRoot, &UserLogin);
		}
		else
		{
			printf("��¼�볬������Ա�û���Ϣ��ʹ��\n");
			User_Push_front(&UserRoot, MASTER);
			while (1)
			{
				printf("\nҪ��������û���(Y/N):");
				if (!YN_qus_1())
				{
					system("cls");
					break;
				}
				printf("ѡ��Ҫ��ӵ��û�����(1����ͨ�û� 2������Ա�˻� 3����������Ա�˻�)��");
				int user_type_cho;
				while (scanf("%d", &user_type_cho))
				{
					if (user_type_cho > 0 && user_type_cho < 4)
						break;
				}
				User_Push_front(&UserRoot, user_type_cho);
			}
			userLogin(UserRoot, &UserLogin);
		}
		//������
		while (1)
		{
			if (!UserLogin)
			{
				system("color C0");
				for (int i = 0; i < 3; ++i)
				{
					printf("�˻��쳣���ܾ����ʣ�\n");
					Sleep(200);
					system("cls");
					Sleep(200);
				}
				break;
			}
			system("color 70");
			printf("�豸����ϵͳ BY.BLADEHIKER\n");
			//���ݿ�ˢ��
			User_f5_echo(UserRoot);
			Dev_f5_echo(DevRoot);
			Use_f5_echo(DevRoot);
			printf("��ǰ�û���[%s]%s(%s)\n", (UserLogin->level == 1) ? "��ͨ�û�" : (UserLogin->level == 2) ? "����Ա" : "��������Ա", UserLogin->name, UserLogin->userID);
			printf("��ǰλ�ã�/���˵�\n\n");
			printf("1.�豸����\n");
			printf("2.�豸����\n");
			printf("3.�û�����\n");
			printf("4.�������\n");
			printf("5.�˳���¼\n");
			printf("��ѡ���ܱ��(1,2,3,4,5):");
			int menu_main_cho;
			while (1)
			{
				scanf("%d", &menu_main_cho);
				if (menu_main_cho > 0 && menu_main_cho < 6)
					break;
			}
			if (menu_main_cho == 1)
			{
				while (1)
				{
					Dev_f5_echo(DevRoot);
					system("color F1");
					system("cls");
					printf("�豸����ϵͳ BY.BLADEHIKER\n");
					printf("��ǰ�û���[%s]%s(%s)\n", (UserLogin->level == 1) ? "��ͨ�û�" : (UserLogin->level == 2) ? "����Ա" : "��������Ա", UserLogin->name, UserLogin->userID);
					printf("��ǰλ�ã�/���˵�/�豸����\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�����豸\n");
						printf("��ѡ���ܱ��(1,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//�豸���� ���޸�Ȩ��
							Dev_find(DevRoot);
						}
					}
					else
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�����豸\n");
						printf("2.¼�����豸\n");
						printf("��ѡ���ܱ��(1,2,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//�����豸 �����޸� ȫ���ܰ�
							struct Device *DevCho = Dev_find(DevRoot);
							if (DevCho)
							{
								printf("��ѡ���豸\n");
								printf("�豸ID��%lld\t�豸�ͺţ�%s\t�豸���ƣ�%s\n", DevCho->deviceID, DevCho->type, DevCho->name);
								printf("0.�����ϼ��˵�\n");
								printf("1.�޸���ѡ�豸\n");
								printf("2.ɾ����ѡ�豸\n");
								printf("��ѡ����(0,1,2):");
								int choose_ssub;
								while (1)
								{
									scanf("%d", &choose_ssub);
									if (choose_ssub == 0 || choose_ssub == 1 || choose_ssub == 2)
										break;
								}
								if (choose_ssub == 0)
								{
									continue;
								}
								else if (choose_ssub == 1)
								{
									//�޸��豸
									Dev_edit(DevCho);
								}
								else if (choose_ssub == 2)
								{
									//ɾ���豸
									printf("�����Ҫɾ����ѡ�豸��(Y/N)��");
									if (YN_qus_1())
									{
										Dev_del(&DevRoot, DevCho);
										printf("ɾ���ɹ���\n");
									}
									else
									{
										printf("��ȡ���������豸δɾ����");
									}
								}
							}
						}
						else if (menu_sub_cho == 2)
						{
							//¼�����豸
							system("cls");
							Dev_push_front(&DevRoot);
						}
					}
					system("pause");
					system("cls");
				}
			}
			else if (menu_main_cho == 2)
			{
				while (1)
				{
					Use_f5_echo(DevRoot);
					system("color F2");
					system("cls");
					printf("�豸����ϵͳ BY.BLADEHIKER\n");
					printf("��ǰ�û���[%s]%s(%s)\n", (UserLogin->level == 1) ? "��ͨ�û�" : (UserLogin->level == 2) ? "����Ա" : "��������Ա", UserLogin->name, UserLogin->userID);
					printf("��ǰλ�ã�/���˵�/�豸����\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�����豸\n");
						printf("2.�黹�豸\n");
						printf("��ѡ���ܱ��(1,2,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//����
							Use_Push_front(DevRoot, UserLogin);
						}
						else
						{
							//�黹
							Use_Back(DevRoot, UserLogin);
						}
					}
					else
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�����豸\n");
						printf("2.�黹�豸\n");
						printf("3.���ü�¼��ѯ\n");
						printf("��ѡ���ܱ��(1,2,3,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2 || menu_sub_cho == 3)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//����
							Use_Push_front(DevRoot, UserLogin);
						}
						else if (menu_sub_cho == 2)
						{
							//�黹
							Use_Back(DevRoot, UserLogin);
						}
						else
						{
							//ȫ���ܼ�¼��ѯ
							Use_View(DevRoot, UserRoot);
						}
					}
				}
			}
			else if (menu_main_cho == 3)
			{
				while (1)
				{
					User_f5_echo(UserRoot);
					if (!UserLogin)
					{
						system("color C0");
						for (int i = 0; i < 3; ++i)
						{
							printf("�˻��쳣���ܾ����ʣ�\n");
							Sleep(200);
							system("cls");
							Sleep(200);
						}
						break;
					}
					system("color F4");
					system("cls");
					printf("�豸����ϵͳ BY.BLADEHIKER\n");
					printf("��ǰ�û���[%s]%s(%s)\n", (UserLogin->level == 1) ? "��ͨ�û�" : (UserLogin->level == 2) ? "����Ա" : "��������Ա", UserLogin->name, UserLogin->userID);
					printf("��ǰλ�ã�/���˵�/�û�����\n\n");
					if (UserLogin->level == 1)
					{
						printf("����Ȩ���ʴ���Ŀ��\n");
						system("pause");
						system("cls");
						break;
					}
					else if (UserLogin->level == 2)
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�����ͨ�û�\n");
						printf("2.ɾ����ͨ�û�\n");
						printf("��ѡ���ܱ��(1,2,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//�����ͨ�û�
							User_Push_front(&UserRoot, 1);
							printf("����û��ɹ���\n");
							system("pause");
						}
						else if (menu_sub_cho == 2)
						{
							struct User *User_Cho_pop = User_find_1(UserRoot);
							if (User_Cho_pop)
							{
								User_pop(&UserRoot, User_Cho_pop);
								system("pause");
							}
						}
					}
					else
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.����û�\n");
						printf("2.���/ɾ���û�\n");
						printf("��ѡ���ܱ��(1,2,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//����û�
							printf("ѡ��Ҫ��ӵ��û�����(1����ͨ�û� 2������Ա�˻� 3����������Ա�˻�)��");
							int user_type_cho;
							while (1)
							{
								scanf("%d", &user_type_cho);
								if (user_type_cho > 0 && user_type_cho < 4)
									break;
							}
							User_Push_front(&UserRoot, user_type_cho);
							printf("����û��ɹ���\n");
							system("pause");
						}
						else if (menu_sub_cho == 2)
						{
							//���
							User_cha(&UserRoot, &UserLogin);
						}
					}
				}
			}
			else if (menu_main_cho == 4)
			{
				while (1)
				{
					system("color F5");
					system("cls");
					printf("�豸����ϵͳ BY.BLADEHIKER\n");
					printf("��ǰ�û���[%s]%s(%s)\n", (UserLogin->level == 1) ? "��ͨ�û�" : (UserLogin->level == 2) ? "����Ա" : "��������Ա", UserLogin->name, UserLogin->userID);
					printf("��ǰλ�ã�/���˵�/�������\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�豸����\n");
						printf("��ѡ���ܱ��(1,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else
						{
							//�豸��������
							Device_rep_out(DevRoot);
							printf("�豸����Device_report.txt���ɳɹ�\n");
							system("pause");
						}
					}
					else
					{
						printf("0.�����ϼ��˵�\n");
						printf("1.�豸����\n");
						printf("2.���ñ���\n");
						printf("3.��Ա����\n");
						printf("��ѡ���ܱ��(1,2,3,0):");
						int menu_sub_cho;
						while (1)
						{
							scanf("%d", &menu_sub_cho);
							if (menu_sub_cho == 0 || menu_sub_cho == 1 || menu_sub_cho == 2 || menu_sub_cho == 3)
							{
								break;
							}
						}
						if (menu_sub_cho == 0)
						{
							system("cls");
							break;
						}
						else if (menu_sub_cho == 1)
						{
							//�豸����
							Device_rep_out(DevRoot);
							printf("�豸����Device_report.txt���ɳɹ�\n");
							system("pause");
						}
						else if (menu_sub_cho == 2)
						{
							//���ñ���
							Use_rep_out(DevRoot);
							printf("���ñ���Use_report.txt���ɳɹ�\n");
							system("pause");
						}
						else if (menu_sub_cho == 3)
						{
							//�û�����
							User_rep_out(UserRoot);
							printf("�û�����User_report.txt���ɳɹ�\n");
							system("pause");
						}
					}
				}
			}
			else if (menu_main_cho == 5)
			{
				system("color F0");
				system("cls");
				printf("�����Ҫ�˳���¼��(Y/N)");
				if (!YN_qus_1())
				{
					system("cls");
					continue;
				}
				else
				{
					UserLogin = 0;
					system("cls");
					User_f5_echo(UserRoot);
					Dev_f5_echo(DevRoot);
					Use_f5_echo(DevRoot);
					break;
				}
			}
		}
	}
	Free_d(DevRoot, UserRoot);
	return 0;
}