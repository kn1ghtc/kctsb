//
//  baseFinance.cpp
//  kcalg
//
//  Created by knightc on 2019/7/3.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

#include "opentsb/cplus.h"
#include "testStruct.h"

//固定收益
/*设置初始资金为 a
 * 设置年化收益率为 b
 * 投资年限为 n
 *每年末追加金额 x
 */

FinanceData kcData1;//引用的数据结构也只能在其他函数体内使用，全局只做声明

void fixed_income(double a,double b,double x, int n) {
    

    //a1=a*（1+b）+x
    //a2=a1*（1+b）+x
    double incomeArry[n+1];
    incomeArry[0]=a;
    for (int i=1; i<=n; i++) {
        incomeArry[i] = incomeArry[i-1]* (1+b) +x;
        
    }
    for (int i=1; i<=n; i++) {
        printf("the %d years's income is %f \n",i,incomeArry[i]);
    }
    
}


