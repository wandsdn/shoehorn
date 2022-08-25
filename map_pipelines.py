import shoehorn
import sys
import yaml
import inspect


hw_filename = sys.argv[1]
sw_filename = sys.argv[2]

with open(hw_filename, 'r') as hwf:
    hw_data = yaml.safe_load(hwf)

with open(sw_filename, 'r') as swf:
    sw_data = yaml.safe_load(swf)

hw_pipeline = shoehorn.Pipeline(hw_filename, hw_data)
sw_pipeline = shoehorn.Pipeline(sw_filename, sw_data)

results = hw_pipeline.map(sw_pipeline)

print("========COMPLETE CMAPS==========")
cmap = results[0]
cmap.resolve_gotos()
print(yaml.dump(cmap.to_json_data()))
