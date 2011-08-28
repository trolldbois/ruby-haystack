/*
 * example programme for ruby-haystack
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define RED   10
#define BLUE  11
#define GREEN 12
#define YELLOW 13

#define MAGIC 0xff112233


typedef enum {
    VALUE_A0,
    VALUE_A1,
    VALUE_A2,
    VALUE_A3,
    VALUE_A4,
    VALUE_A5,
    VALUE_A6,
    VALUE_A7,
    VALUE_A8,
    VALUE_A9
} ;

struct brand {
    int brandmagic;
    char * brandname;
} ;
typedef struct brand Brand;

typedef struct sister Sister;

struct sister {
    int id;
    Sister * sister;
} ;
//typedef struct sister Sister;

struct car {
    int magic1;
    char * name;
    int color;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;
    char name2[255];
    Brand brand;
    Brand * p_brand;
    Sister * sis;
} ;

typedef struct car Car;


int main(int argc, char* argv)
{
    Car * car;
    Sister * s1,*s2,*s3;
    char name[] = "my nice little car";
    
    car = (Car *)malloc(sizeof(Car) );
    printf("Car has been allocated\n");
    car->magic1 = MAGIC ;
    car->name = (char *)malloc(256);
    strcpy(car->name, name);
    strcpy(car->name2, name);
    car->color = BLUE;
    car->a1 = VALUE_A1;
    car->a2 = VALUE_A2;
    car->a3 = VALUE_A3;
    car->a4 = VALUE_A4;
    car->a5 = VALUE_A5;
    printf("car has been initialized\n");
    car->brand.brandname = (char *)malloc(256);
    strcpy(car->brand.brandname, "Peugeot");
    car->brand.brandmagic = MAGIC ;
    printf("brand has been initialized\n");
    car->p_brand = (Brand *)malloc(sizeof(Brand));
    car->p_brand->brandname = (char *)malloc(256);
    strcpy(car->p_brand->brandname, "Citroen");
    car->p_brand->brandmagic = MAGIC ;
    printf("p_brand has been initialized\n");
    s1 = (Sister *)malloc(sizeof(Sister));
    s2 = (Sister *)malloc(sizeof(Sister));
    s3 = (Sister *)malloc(sizeof(Sister));
    s1->id = 1;
    s1->sister = s2;
    s2->id = 2;
    s2->sister = s3;
    s3->id = 3;
    s3->sister = s1;
    car->sis = s1;
    printf("sisters has been initialized\n");
    

    
    while(1)
      sleep(10000);
    return 0;
}




















