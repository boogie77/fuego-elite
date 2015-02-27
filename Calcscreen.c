#include "Main.h"
#include "Toolset.h"
#include "Sdk.h"
#include "Math.h"
#include "Calcscreen.h"

#define M_PI 3.14159265358979323846
#define BOUND_VALUE(var,min,max) if((var)>(max)){(var)=(max);};if((var)<(min)){(var)=(min);}
#define DotProduct(x,y) ((x)[0]*(y)[0]+(x)[1]*(y)[1]+(x)[2]*(y)[2])

float VectorLength(const vec3_t v)
{
	return (float)sqrt(v[0]*v[0]+v[1]*v[1]+v[2]*v[2]);
}

float VectorAngle(const vec3_t a, const vec3_t b)
{
	float length_a=VectorLength(a);
	float length_b=VectorLength(b);
	float length_ab=length_a*length_b;
	if (length_ab==0.0)
	{
		return 0.0;
	}
	else
	{
		return (float)(acos(DotProduct(a,b)/length_ab)*(180.f/M_PI));
	}
}

void MakeVector(const vec3_t ain, vec3_t vout)
{
	float pitch;
	float yaw;
	float tmp;

	pitch=(float)(ain[0]*M_PI/180);
	yaw=(float)(ain[1]*M_PI/180);
	tmp=(float)cos(pitch);

	vout[0]=(float)(-tmp*-cos(yaw));
	vout[1]=(float)(sin(yaw)*tmp);
	vout[2]=(float)-sin(pitch);
}

void VectorRotateX(const vec3_t in, float angle, vec3_t out)
{
	float a, c, s;

	a=(float)(angle*M_PI/180);
	c=(float)cos(a);
	s=(float)sin(a);
	out[0]=in[0];
	out[1]=c*in[1]-s*in[2];
	out[2]=s*in[1]+c*in[2];
}

void VectorRotateY(const vec3_t in, float angle, vec3_t out)
{
	float a, c, s;

	a=(float)(angle*M_PI/180);
	c=(float)cos(a);
	s=(float)sin(a);
	out[0]=c*in[0]+s*in[2];
	out[1]=in[1];
	out[2]=-s*in[0]+c*in[2];
}

void VectorRotateZ(const vec3_t in, float angle, vec3_t out)
{
	float a, c, s;

	a=(float)(angle*M_PI/180);
	c=(float)cos(a);
	s=(float)sin(a);
	out[0]=c*in[0]-s*in[1];
	out[1]=s*in[0]+c*in[1];
	out[2]=in[2];
}

int WorldToScreen( float* in, float* out, float* mainViewAngles, float* mainViewOrigin,
				  float fCurrentFOV, float fDisplayX, float fDisplayY )
{
	vec3_t aim;
	vec3_t newaim;
	vec3_t view;
	vec3_t tmp;
	float num;

	if (!in || !out)
	{
		return FALSE;
	}

	VectorSubtract(in, mainViewOrigin, aim);
	MakeVector(mainViewAngles, view);

	if (VectorAngle(view, aim)>(fCurrentFOV/1.8))
	{
		return FALSE;
	}

	VectorRotateZ(aim, -mainViewAngles[1], newaim); // yaw
	VectorRotateY(newaim, -mainViewAngles[0], tmp); // pitch
	VectorRotateX(tmp, -mainViewAngles[2], newaim); // roll

	if (newaim[0]<=0)
	{
		return FALSE;
	}

	if (fCurrentFOV==0.0f)
	{
		return FALSE;
	}
	num=(float)((fDisplayX/newaim[0])*(120.0/fCurrentFOV-1.0/3.0));

	out[0]=fDisplayX-num*newaim[1];
	out[1]=fDisplayX-num*newaim[2];


	BOUND_VALUE(out[0], 0, fDisplayX*2);
	BOUND_VALUE(out[1], 0, fDisplayY*2);

	return TRUE;
}
