#buffer size in KB vs time in min
min2mil = 60*1000
suggested_values = [(2^0, 0), (2^17, 1), (2^20, 25), (2^23, 29), (2^27,29.99)]
suggested_values = [(a,b*min2mil) for (a,b) in suggested_values]
exponential_values = [(t,s) for (t,s) in suggested_values]
#RR(e^(1/t))
g = 20 #(max dead)
var('a,b,d,e,f')
#model(x) = a*e^(g/x)+b
c = 1
model(x) = b*(-log(x*c))+d #*(x)^4+c*(x)^3+d*(x)^2+ e*(x) + f 
b,d  = find_fit(suggested_values, model)
print b,c,d
#f(x) = c.rhs()*e^(h.rhs()/x)+d.rhs()
f(x) = b.rhs()*(-log(0.125*x))+d.rhs()#^4+c.rhs()*(x)^3+d.rhs()*(x)^2+ e.rhs()*(x) + f.rhs()
print [(j, RR(f(2^j) - f(1))/(min2mil)) for j in range(0,31)]
