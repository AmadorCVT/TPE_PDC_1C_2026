# Apuntes

## Antes de entregar, compilar en pampero. Porque este va a ser el desempate por si al porfe no le compila o ñe tira warnings en su compu

- Entrega tardía da nota maxima 4

- Va a revisar la participacion en git, tipo si hace todo uno va a ser nota individual, si es parejo nota grupal

- La seccion mas importante del informe es la de problemas encontrados: si sabes que tenes un error conviene mencionarlo en el informe, como te diste cuenta, que intentaste y otras cosas porque seguramente lo encuentre al error de todas formas.

- Hay mucha libertad para muchas cosas, lo ideal es ir testeando distintas implementaciones de lo mismo (por ejemplo, usar 2 buffers por usuario o 4) y decidir en base a eso que hacer yplasmar la toma de esa decision en el informe.
  

- Muy importante usar los parches de los profesores, pues arreglan cosas complicadas en las que no quieren q perdamos tiempo.


### Lo primero que hay q hacer es aplicar los parches, en orden.


## AUTENTICACION
El servidor debe autenticar a los clientes, o hace con una tabla.
El handler utiliza una maquina de estados para saber que tiene que hacer.

## Como arrancar el trabajo
recomendacio: en la primera implementacion no tener nada de sock5, sino tener un echo server que responda de forma optimista. Luego es que se va a ir agregando un handler de lectura para el protocolo socks.

paralelizar entre parsear socks y parsear su propio protocolo

