# 生成5条
python llm_augment.py generate --n 5 --out output_llm 

# 指定场景10条
python llm_augment.py generate --n 10 --out output_llm --scenario DPI,MultiHop,Colluding

# 关闭投票（省钱）20条
python llm_augment.py generate --n 20 --out output_llm --no-vote

# 合并骨架数据 + LLM 数据   
python llm_augment.py merge output_v2 output_llm --out output_final