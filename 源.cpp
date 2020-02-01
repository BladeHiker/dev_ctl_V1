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
//***************MD5算法***************//
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
//***************MD5算法***************//
enum LEVEL
{
	USER = 1,
	ADMIN,
	MASTER
};
struct Device
{
	char type[500]; //型号
	char name[500]; //名称
	double price;   //价格
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
char *ctime_d(time_t *t)//time_t转换为不含换行的字符串
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
bool md5_eq(unsigned char *md51, unsigned char *md52)//MD5密码比对
{
	for (int i = 0; i < 16; ++i)
	{
		if (md51[i] != md52[i])
			return false;
	}
	return true;
}
time_t str2time_t(char str[50])//时间字符串转time_t
{
	time_t tt;
	struct tm ttm;
	char m[5];
	//一月Jan，二月Feb，三月Mar，四月Apr，五月May，六月June，七月July，八月Aug，九月Sept，十月Oct，十一月Nov，十二月Dec。
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
void userLogin(struct User *userRoot, struct User **userLogin)//用户登录
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
				printf("\n欢迎，%s\n", p->name);
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
				printf("\n用户ID或密码错误，请再试一次！\n");
				Sleep(1000);
			}
			else
			{
				system("color C0");
				printf("\n用户ID或密码错误，请%ld分钟后再试!\n", (long)pow(2, (errcnt - 5)));
				Sleep(60 * 1000 * (long)pow(2, (errcnt - 5)));
				system("color 02");
			}
		}
	}
}
void User_Push_front_echo(struct User **UserRoot, char userID[], char name[], int level, unsigned char userpasswd[16])//添加用户
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
void Dev_Push_front_echo(struct Device **DevRoot, char type[500], char name[500], double price, long long deviceID, time_t timein, int state, bool fg_info, char info[10000])//添加设备
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
void Use_Push_front_echo(struct Device *DevRoot, struct User *UserRoot, long long DeviceID, char userID[50], char useBegs[100], int end, char useEnds[100])//添加领用记录
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
void User_db_w(struct User *user)//向数据库写入单个用户信息
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
void Device_db_w(struct Device *Dev)//向数据库写入单个设备信息
{
	FILE *db_Dev = fopen("db_Device.txt", "a+");
	if (db_Dev)
	{
		fprintf(db_Dev, "%s %s %.2lf %lld %s %d %s\n", Dev->type, Dev->name, Dev->price, Dev->deviceID, ctime(&Dev->timein), Dev->fg_info, Dev->fg_info ? Dev->info : "null");
		fclose(db_Dev);
	}
	return;
}
void Use_db_w(struct Use *Use_Cho)//向数据库写入单个领用记录
{
	FILE *db_Use = fopen("db_Use.txt", "a+");
	if (db_Use)
	{
		fprintf(db_Use, "%lld %s %s %d %s\n", Use_Cho->DevUse->deviceID, Use_Cho->user->userID, ctime(&Use_Cho->useBeg), Use_Cho->end, Use_Cho->end ? ctime(&Use_Cho->useEnd) : "null");
		fclose(db_Use);
	}
	return;
}
void User_Push_front(struct User **UserRoot, int level)//添加用户向导
{
	struct User *Userp = (struct User *)malloc(sizeof(struct User));
	Userp->next = *UserRoot;
	*UserRoot = Userp;
	while (1)
	{
		bool fg_if_pass = true;
		printf("输入新用户ID：");
		scanf("%s", Userp->userID);
		for (struct User *up = (*UserRoot)->next; up; up = up->next)
		{
			if (strcmp(up->userID, Userp->userID) == 0)
			{
				printf("用户ID%s已被占用，请更换ID再试\n", Userp->userID);
				fg_if_pass = false;
			}
		}
		if (fg_if_pass)
			break;
	}
	printf("输入用户名：");
	scanf("%s", Userp->name);
	getchar();
	Userp->level = level;
	Userp->usenum = -1;
	bool fg_passwd_ok = true;
	unsigned char userPasswd1[500] = {0}, userPasswd2[500] = {0};
	int passwdlen1 = 0, passwdlen2 = 0;
	while (fg_passwd_ok)
	{
		printf("输入新密码：");
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
			printf("\n重复输入密码：");
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
					printf("请再试一次！\n");
				else
				{
					printf("请重试！\n");
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
void dbRead(struct User **UserRoot, struct Device **DevRoot)//读取数据库
{
	system("cls");
	printf("读取数据库中");
	FILE *db_user = fopen("db_user.txt", "r");
	FILE *db_device = fopen("db_device.txt", "r");
	FILE *db_use = fopen("db_use.txt", "r");
	char userID[50], name[100];
	int level;
	unsigned char userpasswd[50];
	if (db_user)
	{
		printf("\n-》》》用户数据库");
		while (~fscanf(db_user, "%s %s %d ", userID, name, &level))
		{
			for (int i = 0; i < 16; ++i)
				fscanf(db_user, "%02x", &userpasswd[i]);
			fscanf(db_user, "\n");
			User_Push_front_echo(UserRoot, userID, name, level, userpasswd);
			printf("》");
		}
		fclose(db_user);
		printf("\n用户数据库读取完成！\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("\n用户数据库读取失败！\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("\n用户数据库读取失败！\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	if (db_device)
	{
		printf("\n-》》》设备数据库");
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
			printf("》");
		}
		fclose(db_device);
		printf("\n设备数据库读取完成！\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("设备数据库读取失败！\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("设备数据库读取失败！\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	if (db_use)
	{
		printf("\n-》》》领用数据库");
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
			printf("》");
		}
		fclose(db_use);
		printf("\n领用数据库读取完成！\n");
	}
	else
	{
		system("cls");
		system("color 0C");
		printf("\n领用数据库读取失败！\n");
		Sleep(500);
		system("cls");
		Sleep(200);
		printf("\n领用数据库读取失败！\n");
		Sleep(500);
		system("cls");
		system("color 02");
		return;
	}
	system("cls");
	return;
}
bool YN_qus_0(bool deft)//判断输入Y/N
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
bool YN_qus_1()//判断输入Y/N
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
void Dev_push_front(struct Device **DevRoot)//添加设备向导
{
	struct Device *Devp = (struct Device *)malloc(sizeof(struct Device));
	Devp->dlink = *DevRoot;
	*DevRoot = Devp;
	printf("录入新设备\n");
	printf("请输入设备型号：");
	scanf("%s", Devp->type);
	printf("请输入设备名称：");
	scanf("%s", Devp->name);
	printf("请输入设备价格：￥");
	scanf("%lf", &Devp->price);
	while (1)
	{
		bool fg_id_pass = true;
		printf("请输入设备ID(仅有阿拉伯数字构成)：");
		scanf("%lld", &Devp->deviceID);
		for (struct Device *dp = (*DevRoot)->dlink; dp; dp = dp->dlink)
		{
			if (dp->deviceID == Devp->deviceID)
			{
				printf("设备ID%lld已被占用，请更换ID再试！\n", Devp->deviceID);
				fg_id_pass = false;
			}
		}
		if (fg_id_pass)
			break;
	}

	Devp->uRoot = 0;
	printf("是否输入备注？(Y/N)：");
	Devp->fg_info = YN_qus_1();
	if (Devp->fg_info)
	{
		printf("请输入备注信息：\n");
		scanf("%s", Devp->info);
	}
	time(&Devp->timein);
	Devp->state = true;
	system("cls");
	printf("设备录入成功！%s\n", ctime_d(&Devp->timein));
	printf("型号：%s\t名称：%s\t价格：￥%.2lf\t设备ID：%lld\t备注：%s\n", Devp->type, Devp->name, Devp->price, Devp->deviceID, Devp->fg_info ? Devp->info : "无备注");
}
struct Device *Dev_find(struct Device *DevRoot)//设备查找模块
{
	printf("设备检索\n");
	printf("0.返回上级菜单\n");
	printf("1.通过设备ID检索\n");
	printf("2.通过设备型号检索\n");
	printf("3.通过设备名称检索\n");
	printf("请选择检索方式(0,1,2,3)：");
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
		printf("请输入合法设备ID：");
		long long ID_find;
		scanf("%lld", &ID_find);
		for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
		{
			if (dp->deviceID == ID_find)
			{
				printf("查询到设备！\n");
				printf("型号：%s\t名称：%s\t价格：￥%.2lf\t设备ID：%lld\t录入时间：%s\t备注：%s\n", dp->type, dp->name, dp->price, dp->deviceID, ctime_d(&dp->timein), dp->fg_info ? dp->info : "无备注");
				return dp;
			}
		}
		printf("找不到ID%lld的设备，请核对后再试！\n", ID_find);
		//system("pause");
		return 0;
	}
	else if (menu_choose == 2)
	{
		printf("请输入要查询的设备型号关键字：");
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
					printf("找到如下设备：\n");
					printf("#编号\t设备ID\t型号\t名称\t价格\t录入时间\t\t\t备注\n");
				}
				++find_cnt;
				dFind[find_cnt] = dp;
				printf("#%d.\t%lld\t%s\t%s\t%.2lf\t%s\t%s\n", find_cnt, dp->deviceID, dp->type, dp->name, dp->price, ctime_d(&dp->timein), dp->fg_info ? dp->info : "无备注");
			}
		}
		if (!find_cnt)
		{
			printf("找不到型号中包含此关键字的设备，请再试一次！\n");
			system("pause");
			return 0;
		}
		else
		{
			printf("找到%d条设备信息!", find_cnt);
			if (find_cnt == 1)
			{
				return dFind[find_cnt];
			}
			else
			{
				printf("请输入所查记录对应编号(1~%d)", find_cnt);
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
		printf("请输入要查询的设备名称关键字：");
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
					printf("找到如下设备：\n");
					printf("#编号\t设备ID\t型号\t名称\t价格\t录入时间\t\t备注\n");
				}
				++find_cnt;
				dFind[find_cnt] = dp;
				printf("#%d.\t%lld\t%s\t%s\t%.2lf\t%s\t%s\n", find_cnt, dp->deviceID, dp->type, dp->name, dp->price, ctime_d(&dp->timein), dp->fg_info ? dp->info : "无备注");
			}
		}
		if (!find_cnt)
		{
			printf("找不到型号中包含此关键字的设备，请再试一次！\n");
			system("pause");
			return 0;
		}
		else
		{
			printf("找到%d条设备信息!", find_cnt);
			if (find_cnt == 1)
			{
				return dFind[find_cnt];
			}
			else
			{
				printf("请输入所查记录对应编号(1~%d)", find_cnt);
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
void Dev_edit(struct Device *DevCho)//设备编辑模块
{
	while (1)
	{
		system("cls");
		printf("当前选定设备：");
		printf("型号：%s\t名称：%s\t价格：￥%.2lf\t设备ID：%lld\t录入时间：%s\t备注：%s\n", DevCho->type, DevCho->name, DevCho->price, DevCho->deviceID, ctime_d(&DevCho->timein), DevCho->fg_info ? DevCho->info : "无备注");
		printf("0.结束修改\n");
		printf("1.修改型号\n");
		printf("2.修改名称\n");
		printf("3.修改价格\n");
		printf("4.修改备注\n");
		printf("输入编号选择修改项(0,1,2,3,4)：");
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
			printf("要将型号修改为：");
			scanf("%s", DevCho->type);
		}
		else if (choose_menu == 2)
		{
			printf("要将名称修改为：");
			scanf("%s", DevCho->name);
		}
		else if (choose_menu == 3)
		{
			printf("要将价格修改为：");
			scanf("%lf", &DevCho->price);
		}
		else if (choose_menu == 4)
		{
			if (!DevCho->fg_info)
			{
				printf("输入新备注：");
				DevCho->fg_info = true;
			}
			else
			{
				printf("要将备注修改为：");
			}
			scanf("%s", DevCho->info);
		}
		printf("修改成功！\n");
		system("pause");
	}
}
void Dev_del(struct Device **DevRoot, struct Device *DevCho)//设备删除功能
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
void Use_Push_front(struct Device *DevRoot, struct User *UserLogin)//领用记录添加
{
	printf("请选择要领用的设备！\n");
	struct Device *DevCho = 0;
	DevCho = Dev_find(DevRoot);
	if (!DevCho)
	{
		printf("未选择设备，请重试！\n");
		return;
	}
	if (DevCho->state)
	{
		printf("正在以当前用户【%s】身份领用\n", UserLogin->name);
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
		printf("领用成功，领用开始时间：%s", ctime_d(&up->useBeg));
		system("pause");
	}
	else
	{
		printf("设备已被领用，请选择其他设备！\n");
		system("pause");
	}
	return;
}
void Use_Back(struct Device *DevRoot, struct User *UserLogin)//归还设备
{
	printf("请选择要归还的设备！\n");
	struct Device *DevCho = 0;
	DevCho = Dev_find(DevRoot);
	if (!DevCho)
	{
		printf("未选择设备，请重试！\n");
		system("pause");
		return;
	}
	printf("正在归还\n");
	struct Use *Up;
	for (struct Use *up = DevCho->uRoot; up; up = up->link)
	{
		printf(".");
		if (up->user == UserLogin)
		{
			time(&up->useEnd);
			up->end = true;
			DevCho->state = true;
			printf("\n归还成功！归还时间：%s\n", ctime_d(&up->useEnd));
			system("pause");
			return;
		}
	}
	printf("找不到您的领用记录，归还失败！\n");
	system("pause");
	return;
}
struct User *User_find(struct User *UserRoot)//查找用户
{
	printf("选择用户\n");
	printf("0.返回上级菜单\n");
	printf("1.通过用户ID检索用户\n");
	printf("2.列出全部用户\n");
	printf("请输入编号来选择功能(0,1,2)：");
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
		printf("请输入用户ID:");
		scanf("%s", &User_ind);
		for (struct User *p = UserRoot; p; p = p->next)
		{
			if (strcmp(User_ind, p->userID) == 0)
			{
				printf("检索到用户:\n");
				printf("[%s]%s(%s)\n", (p->level == 1) ? "普通用户" : (p->level == 2) ? "管理员" : "超级管理员", p->name, p->userID);
				return p;
			}
		}
		printf("找不到用户！\n");
		system("pause");
	}
	else
	{
		struct User *users[20] = {0};
		int cnt = 1;
		for (struct User *p = UserRoot; p; p = p->next)
		{
			printf("#%d.[%s]%s(%s)\n", cnt, (p->level == 1) ? "普通用户" : (p->level == 2) ? "管理员" : "超级管理员", p->name, p->userID);
			users[cnt] = p;
			cnt++;
			if (cnt == 11 || !p->next)
			{
				if (!p->next)
				{
					printf("\n#以上是全部用户#\n\n");
				}
				printf("输入用户前编号选择用户或输入0翻页(0,%d~%d):", 1, cnt - 1);
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
						printf("以上是全部用户！未选中用户，请再试一次\n");
						system("pause");
						return 0;
					}
				}
				else
				{
					printf("检索到用户:\n");
					printf("[%s]%s(%s)\n", (users[t]->level == 1) ? "普通用户" : (users[t]->level == 2) ? "管理员" : "超级管理员", users[t]->name, users[t]->userID);
					system("pause");
					return users[t];
				}
				cnt = 1;
			}
		}
	}
}
struct User *User_find_1(struct User *UserRoot)//查找普通用户
{
	printf("选择用户\n");
	printf("0.返回上级菜单\n");
	printf("1.通过用户ID检索普通用户\n");
	printf("2.列出全部普通用户\n");
	printf("请输入编号来选择功能(0,1,2)：");
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
		printf("请输入用户ID:");
		scanf("%s", &User_ind);
		for (struct User *p = UserRoot; p; p = p->next)
		{
			if (strcmp(User_ind, p->userID) == 0 && p->level == USER)
			{
				printf("检索到用户:\n");
				printf("[%s]%s(%s)\n", (p->level == 1) ? "普通用户" : (p->level == 2) ? "管理员" : "超级管理员", p->name, p->userID);
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
				printf("#%d.[%s]%s(%s)\n", cnt, (p->level == 1) ? "普通用户" : (p->level == 2) ? "管理员" : "超级管理员", p->name, p->userID);
				users[cnt] = p;
				cnt++;
			}
			if (cnt == 11 || !p->next)
			{
				if (!p->next)
				{
					printf("\n#以上是全部普通用户#\n\n");
				}
				printf("输入用户前编号选择用户或输入0翻页(0,1~%d):", cnt - 1);
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
						printf("以上是全部普通用户！未选中用户，请再试一次\n");
						system("pause");
						return 0;
					}
				}
				else
				{
					printf("检索到用户:\n");
					printf("[%s]%s(%s)\n", (users[t]->level == 1) ? "普通用户" : (users[t]->level == 2) ? "管理员" : "超级管理员", users[t]->name, users[t]->userID);
					system("pause");
					return users[t];
				}
				cnt = 1;
			}
		}
	}
	printf("找不到用户！\n");
	system("pause");
	return 0;
}
void Use_View(struct Device *DevRoot, struct User *UserRoot)//查询领用记录
{
	printf("设备领用情况查询\n");
	printf("0.返回上级菜单\n");
	printf("1.查询用户领用情况\n");
	printf("2.查询设备被领用情况\n");
	printf("3.查询全部领用情况\n");
	printf("请选择功能编号(1,2,3,0)：");
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
				printf("用户%s无领用设备记录\n", UserCho->name);
				system("pause");
				return;
			}
			else
			{
				printf("以下是用户%s的全部领用记录\n", UserCho->name);
				for (int i = 0; i <= UserCho->usenum; ++i)
				{
					printf("设备名称：%s\t设备ID：%lld\t领用时间：%s\t", UserCho->uselst[i]->DevUse->name, UserCho->uselst[i]->DevUse->deviceID, ctime_d(&UserCho->uselst[i]->useBeg));
					if (UserCho->uselst[i]->end)
					{
						printf("归还时间%s\n", ctime_d(&UserCho->uselst[i]->useEnd));
					}
					else
					{
						printf("未归还设备\n");
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
					printf("领用人：[%s]%s(%s)\t", (p->user->level == 1) ? "普通用户" : (p->user->level == 2) ? "管理员" : "超级管理员", p->user->name, p->user->userID);
					printf("领用时间：%s\t", ctime_d(&p->useBeg));
					if (p->end)
					{
						printf("归还时间%s\n", ctime_d(&p->useEnd));
					}
					else
					{
						printf("未归还设备\n");
					}
				}
			}
			else
			{
				printf("此设备暂无领用记录\n");
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
				printf("设备名称：%s\t设备ID%lld\t", up->DevUse->name, up->DevUse->deviceID);
				printf("领用人：[%s]%s(%s)\t", (up->user->level == 1) ? "普通用户" : (up->user->level == 2) ? "管理员" : "超级管理员", up->user->name, up->user->userID);
				printf("领用时间：%s\t", ctime_d(&up->useBeg));
				if (up->end)
				{
					printf("归还时间：%s\n", ctime_d(&up->useEnd));
				}
				else
				{
					printf("未归还设备\n");
				}
			}
		}
		if (!fg_print)
		{
			printf("所有设备均无领用记录\n");
		}
		system("pause");
		return;
	}
	system("pause");
	return;
}
void Device_rep_out(struct Device *DevRoot)//设备报表
{
	FILE *Device_rep = fopen("Device_report.txt", "w+");
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		fprintf(Device_rep, "设备ID：%lld\t设备名称：%s\t价格：%.2lf\t入库时间：%s\t在库状态：%s\t备注：%s\n", dp->deviceID, dp->name, dp->price, ctime_d(&dp->timein), dp->state ? "在库" : "借出", dp->fg_info ? dp->info : "无备注");
	}
	fclose(Device_rep);
	return;
}
void User_rep_out(struct User *UserRoot)//用户报表
{
	FILE *User_rep = fopen("User_report.txt", "w+");
	for (struct User *up = UserRoot; up; up = up->next)
	{
		fprintf(User_rep, "用户ID：%s\t用户名：%s\t用户组：%s\n", up->userID, up->name, (up->level == 1) ? "普通用户" : (up->level == 2) ? "管理员" : "超级管理员");
	}
	fclose(User_rep);
	return;
}
void Use_rep_out(struct Device *DevRoot)//领用报表
{
	FILE *Use_rep = fopen("Use_report.txt", "w+");
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		for (struct Use *up = dp->uRoot; up; up = up->link)
		{
			fprintf(Use_rep, "设备名称：%s\t设备ID%lld\t", up->DevUse->name, up->DevUse->deviceID);
			fprintf(Use_rep, "领用人：[%s]%s(%s)\t", (up->user->level == 1) ? "普通用户" : (up->user->level == 2) ? "管理员" : "超级管理员", up->user->name, up->user->userID);
			fprintf(Use_rep, "领用时间：%s\t", ctime_d(&up->useBeg));
			if (up->end)
			{
				fprintf(Use_rep, "归还时间：%s\n", ctime_d(&up->useEnd));
			}
			else
			{
				fprintf(Use_rep, "未归还设备\n");
			}
		}
	}
	fclose(Use_rep);
	return;
}
void User_pop(struct User **UserRoot, struct User *UserCho)//删除用户
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
	printf("已删除用户\n");
	return;
}
void User_cha(struct User **UserRoot, struct User **UserLogin)//用户权限修改
{
	struct User *User_Cho = User_find(*UserRoot);
	if (User_Cho)
	{
		printf("0.返回上级菜单\n");
		printf("1.修改选定用户权限\n");
		printf("2.删除选定用户\n");
		printf("请输入编号选择功能(0,1,2)：");
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
			printf("当前权限为[%s],请选择要所选用户的新权限组(1.普通用户2.管理员3.超级管理员)", (User_Cho->level == 1) ? "普通用户" : (User_Cho->level == 2) ? "管理员" : "超级管理员");
			int menu_sub;
			while (1)
			{
				scanf("%d", &menu_sub);
				if (menu_cho > 0 && menu_cho < 4)
					break;
			}
			User_Cho->level = menu_sub;
			printf("%s的用户权限已修改为[%s]\n", User_Cho->name, (User_Cho->level == 1) ? "普通用户" : (User_Cho->level == 2) ? "管理员" : "超级管理员");
			system("pause");
			return;
		}
		else if (menu_cho == 2)
		{
			printf("你真的要删除此用户吗？(Y/N)：\n");
			if (YN_qus_1())
			{
				if (User_Cho == *UserLogin)
				{
					printf("登录中的账户将被删除，请退出登录以完成删除操作！\n");
					*UserLogin = 0;
				}
				User_pop(UserRoot, User_Cho);
			}
			else
			{
				printf("已取消操作\n");
			}
			system("pause");
		}
	}
}
void User_f5_echo(struct User *UserRoot)//刷新用户数据库
{
	FILE *f = fopen("db_User.txt", "w+");
	fclose(f);
	for (struct User *up = UserRoot; up; up = up->next)
	{
		User_db_w(up);
	}
	return;
}
void Dev_f5_echo(struct Device *DevRoot)//刷新设备数据库
{
	FILE *f = fopen("db_Device.txt", "w+");
	fclose(f);
	for (struct Device *dp = DevRoot; dp; dp = dp->dlink)
	{
		Device_db_w(dp);
	}
	return;
}
void Use_f5_echo(struct Device *DevRoot)//刷新领用记录数据库
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
	printf("设备管理系统 V1 for Windows By.BladeHiker\n");
	for (int i = 0; i < 40; ++i)
	{
		printf(">");
		Sleep(121 - i * 3);
	}
	Sleep(500);
	system("cls");
	//登录用户公示
	struct User *UserLogin = 0;
	//用户根指针
	struct User *UserRoot = 0;
	//设备根指针
	struct Device *DevRoot = 0;
	//数据库读取
	dbRead(&UserRoot, &DevRoot);
	while (1)
	{
		system("color 02");
		//判断用户数据库是否存在
		if (UserRoot)
		{
			userLogin(UserRoot, &UserLogin);
		}
		else
		{
			printf("请录入超级管理员用户信息后使用\n");
			User_Push_front(&UserRoot, MASTER);
			while (1)
			{
				printf("\n要添加其他用户吗？(Y/N):");
				if (!YN_qus_1())
				{
					system("cls");
					break;
				}
				printf("选择要添加的用户类型(1：普通用户 2：管理员账户 3：超级管理员账户)：");
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
		//主界面
		while (1)
		{
			if (!UserLogin)
			{
				system("color C0");
				for (int i = 0; i < 3; ++i)
				{
					printf("账户异常！拒绝访问！\n");
					Sleep(200);
					system("cls");
					Sleep(200);
				}
				break;
			}
			system("color 70");
			printf("设备管理系统 BY.BLADEHIKER\n");
			//数据库刷新
			User_f5_echo(UserRoot);
			Dev_f5_echo(DevRoot);
			Use_f5_echo(DevRoot);
			printf("当前用户：[%s]%s(%s)\n", (UserLogin->level == 1) ? "普通用户" : (UserLogin->level == 2) ? "管理员" : "超级管理员", UserLogin->name, UserLogin->userID);
			printf("当前位置：/主菜单\n\n");
			printf("1.设备管理\n");
			printf("2.设备领用\n");
			printf("3.用户管理\n");
			printf("4.报表输出\n");
			printf("5.退出登录\n");
			printf("请选择功能编号(1,2,3,4,5):");
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
					printf("设备管理系统 BY.BLADEHIKER\n");
					printf("当前用户：[%s]%s(%s)\n", (UserLogin->level == 1) ? "普通用户" : (UserLogin->level == 2) ? "管理员" : "超级管理员", UserLogin->name, UserLogin->userID);
					printf("当前位置：/主菜单/设备管理\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.返回上级菜单\n");
						printf("1.检索设备\n");
						printf("请选择功能编号(1,0):");
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
							//设备检索 无修改权限
							Dev_find(DevRoot);
						}
					}
					else
					{
						printf("0.返回上级菜单\n");
						printf("1.检索设备\n");
						printf("2.录入新设备\n");
						printf("请选择功能编号(1,2,0):");
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
							//检索设备 可以修改 全功能版
							struct Device *DevCho = Dev_find(DevRoot);
							if (DevCho)
							{
								printf("已选择设备\n");
								printf("设备ID：%lld\t设备型号：%s\t设备名称：%s\n", DevCho->deviceID, DevCho->type, DevCho->name);
								printf("0.返回上级菜单\n");
								printf("1.修改已选设备\n");
								printf("2.删除已选设备\n");
								printf("请选择功能(0,1,2):");
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
									//修改设备
									Dev_edit(DevCho);
								}
								else if (choose_ssub == 2)
								{
									//删除设备
									printf("你真的要删除所选设备吗？(Y/N)：");
									if (YN_qus_1())
									{
										Dev_del(&DevRoot, DevCho);
										printf("删除成功！\n");
									}
									else
									{
										printf("已取消操作，设备未删除。");
									}
								}
							}
						}
						else if (menu_sub_cho == 2)
						{
							//录入新设备
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
					printf("设备管理系统 BY.BLADEHIKER\n");
					printf("当前用户：[%s]%s(%s)\n", (UserLogin->level == 1) ? "普通用户" : (UserLogin->level == 2) ? "管理员" : "超级管理员", UserLogin->name, UserLogin->userID);
					printf("当前位置：/主菜单/设备领用\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.返回上级菜单\n");
						printf("1.领用设备\n");
						printf("2.归还设备\n");
						printf("请选择功能编号(1,2,0):");
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
							//领用
							Use_Push_front(DevRoot, UserLogin);
						}
						else
						{
							//归还
							Use_Back(DevRoot, UserLogin);
						}
					}
					else
					{
						printf("0.返回上级菜单\n");
						printf("1.领用设备\n");
						printf("2.归还设备\n");
						printf("3.领用记录查询\n");
						printf("请选择功能编号(1,2,3,0):");
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
							//领用
							Use_Push_front(DevRoot, UserLogin);
						}
						else if (menu_sub_cho == 2)
						{
							//归还
							Use_Back(DevRoot, UserLogin);
						}
						else
						{
							//全功能记录查询
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
							printf("账户异常！拒绝访问！\n");
							Sleep(200);
							system("cls");
							Sleep(200);
						}
						break;
					}
					system("color F4");
					system("cls");
					printf("设备管理系统 BY.BLADEHIKER\n");
					printf("当前用户：[%s]%s(%s)\n", (UserLogin->level == 1) ? "普通用户" : (UserLogin->level == 2) ? "管理员" : "超级管理员", UserLogin->name, UserLogin->userID);
					printf("当前位置：/主菜单/用户管理\n\n");
					if (UserLogin->level == 1)
					{
						printf("您无权访问此项目！\n");
						system("pause");
						system("cls");
						break;
					}
					else if (UserLogin->level == 2)
					{
						printf("0.返回上级菜单\n");
						printf("1.添加普通用户\n");
						printf("2.删除普通用户\n");
						printf("请选择功能编号(1,2,0):");
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
							//添加普通用户
							User_Push_front(&UserRoot, 1);
							printf("添加用户成功！\n");
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
						printf("0.返回上级菜单\n");
						printf("1.添加用户\n");
						printf("2.变更/删除用户\n");
						printf("请选择功能编号(1,2,0):");
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
							//添加用户
							printf("选择要添加的用户类型(1：普通用户 2：管理员账户 3：超级管理员账户)：");
							int user_type_cho;
							while (1)
							{
								scanf("%d", &user_type_cho);
								if (user_type_cho > 0 && user_type_cho < 4)
									break;
							}
							User_Push_front(&UserRoot, user_type_cho);
							printf("添加用户成功！\n");
							system("pause");
						}
						else if (menu_sub_cho == 2)
						{
							//变更
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
					printf("设备管理系统 BY.BLADEHIKER\n");
					printf("当前用户：[%s]%s(%s)\n", (UserLogin->level == 1) ? "普通用户" : (UserLogin->level == 2) ? "管理员" : "超级管理员", UserLogin->name, UserLogin->userID);
					printf("当前位置：/主菜单/报表输出\n\n");
					if (UserLogin->level == 1)
					{
						printf("0.返回上级菜单\n");
						printf("1.设备报表\n");
						printf("请选择功能编号(1,0):");
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
							//设备报表生成
							Device_rep_out(DevRoot);
							printf("设备报表Device_report.txt生成成功\n");
							system("pause");
						}
					}
					else
					{
						printf("0.返回上级菜单\n");
						printf("1.设备报表\n");
						printf("2.领用报表\n");
						printf("3.人员报表\n");
						printf("请选择功能编号(1,2,3,0):");
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
							//设备报表
							Device_rep_out(DevRoot);
							printf("设备报表Device_report.txt生成成功\n");
							system("pause");
						}
						else if (menu_sub_cho == 2)
						{
							//领用报表
							Use_rep_out(DevRoot);
							printf("领用报表Use_report.txt生成成功\n");
							system("pause");
						}
						else if (menu_sub_cho == 3)
						{
							//用户报表
							User_rep_out(UserRoot);
							printf("用户报表User_report.txt生成成功\n");
							system("pause");
						}
					}
				}
			}
			else if (menu_main_cho == 5)
			{
				system("color F0");
				system("cls");
				printf("你真的要退出登录吗？(Y/N)");
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