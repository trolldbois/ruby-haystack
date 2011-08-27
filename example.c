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
} ;

typedef struct car Car;


int main(int argc, char* argv)
{
    Car * car;
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
    car->brand.brandname = (char *)malloc(256);
    strcpy(car->brand.brandname, "Peugeot");
    car->brand.brandmagic = MAGIC ;
    printf("member have been initialized\n");
    
    while(1)
      sleep(10000);
    return 0;
}




















