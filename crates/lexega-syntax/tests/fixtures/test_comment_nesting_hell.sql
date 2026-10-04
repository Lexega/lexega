-- Deeply nested subqueries with comments at every level
/* level 0 start */ SELECT /* l0 select */ /* l0 col */ col1 /* l0 col end */ , /* l0 subq start */ ( /* level 1 start */ SELECT /* l1 select */ /* l1 col */ col2 /* l1 col end */ , /* l1 subq start */ ( /* level 2 start */ SELECT /* l2 select */ /* l2 col */ col3 /* l2 col end */ , /* l2 subq start */ ( /* level 3 start */ SELECT /* l3 select */ /* l3 col */ col4 /* l3 col end */ , /* l3 subq start */ ( /* level 4 start */ SELECT /* l4 select */ /* l4 col */ col5 /* l4 col end */ 
/* l4 from */ FROM /* l4 from kw */ t5 /* l4 table */ 
/* l4 where */ WHERE /* l4 where kw */ id /* l4 id */ = /* l4 eq */ 1 /* l4 one */ /* level 4 end */ ) /* l3 subq end */ AS /* l3 as */ nested4 /* l3 alias */ 
/* l3 from */ FROM /* l3 from kw */ t4 /* l3 table */ 
/* l3 where */ WHERE /* l3 where kw */ id /* l3 id */ = /* l3 eq */ 2 /* l3 two */ /* level 3 end */ ) /* l2 subq end */ AS /* l2 as */ nested3 /* l2 alias */ 
/* l2 from */ FROM /* l2 from kw */ t3 /* l2 table */ 
/* l2 where */ WHERE /* l2 where kw */ id /* l2 id */ = /* l2 eq */ 3 /* l2 three */ /* level 2 end */ ) /* l1 subq end */ AS /* l1 as */ nested2 /* l1 alias */ 
/* l1 from */ FROM /* l1 from kw */ t2 /* l1 table */ 
/* l1 where */ WHERE /* l1 where kw */ id /* l1 id */ = /* l1 eq */ 4 /* l1 four */ /* level 1 end */ ) /* l0 subq end */ AS /* l0 as */ nested1 /* l0 alias */ 
/* l0 from */ FROM /* l0 from kw */ t1 /* l0 table */ 
/* l0 where */ WHERE /* l0 where kw */ id /* l0 id */ = /* l0 eq */ 5 /* l0 five */ /* level 0 end */ ; /* final semi */ 